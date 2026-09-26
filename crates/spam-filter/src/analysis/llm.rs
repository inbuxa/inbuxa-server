/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The language model's opinion as one spam signal (AI spam classification
//! spec, AI-3, AI-4, AI-6, AI-9 to AI-13, AI-16). Any failure leaves the
//! message scored as if the classifier were off.

use crate::{SpamFilterContext, TextPart};
use common::{
    Server,
    config::mailstore::spamfilter::SpamFilterAction,
    enterprise::llm::Call,
};
use inbuxa_features::ai::{answer, request};
use registry::schema::structs::SpamLlm;
use std::future::Future;
use types::id::Id;

pub trait SpamFilterAnalyzeLlm: Sync + Send {
    fn spam_filter_analyze_llm(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeLlm for Server {
    async fn spam_filter_analyze_llm(&self, ctx: &mut SpamFilterContext<'_>) {
        // Read now, so a change applies to the next message (AI-18)
        let Ok(Some(SpamLlm::Enable(settings))) =
            self.registry().object::<SpamLlm>(Id::singleton()).await
        else {
            return;
        };

        // AI-16: local users' own mail isn't sent to a model, and neither is
        // mail another tag already discards or rejects
        if ctx.input.authenticated_as.is_some_and(|a| !a.is_empty())
            || ctx.result.tags.iter().any(|tag| {
                matches!(
                    self.core.spam.lists.scores.get(tag),
                    Some(SpamFilterAction::Discard | SpamFilterAction::Reject)
                )
            })
        {
            return;
        }

        let Some(model) = self.ai_model_by_id(settings.model_id).await else {
            return;
        };
        let limits = self.ai_limits().await;

        // AI-3: the subject and the message's text, nothing else
        let text = ctx
            .output
            .text_parts
            .iter()
            .filter_map(|part| match part {
                TextPart::Plain { text_body, .. } => Some(*text_body),
                TextPart::Html { text_body, .. } => Some(text_body.as_str()),
                TextPart::None => None,
            })
            .collect::<Vec<_>>()
            .join("\n\n");
        let nonce = request::nonce();
        let user = request::classification_text(
            &ctx.output.subject,
            &text,
            limits.max_content_bytes as usize,
            &nonce,
        );
        let system = request::system_text(&settings.prompt);

        // AI-9: never longer than the ceiling, whatever the model's timeout
        let timeout = model
            .timeout
            .into_inner()
            .min(limits.spam_call_ceiling.into_inner());
        let Ok(reply) = self
            .ai_call(Call {
                model_id: settings.model_id,
                model: &model,
                account_id: None,
                system: Some(&system),
                user: &user,
                temperature: settings.temperature.into_inner(),
                max_tokens: request::CLASSIFY_MAX_TOKENS,
                timeout,
                explain: None,
                stream: None,
            })
            .await
        else {
            return;
        };

        let categories = settings.categories.iter().cloned().collect::<Vec<_>>();
        let confidence = settings.confidence.iter().cloned().collect::<Vec<_>>();
        let rules = answer::Rules {
            separator: &settings.separator,
            pos_category: settings.response_pos_category as usize,
            pos_confidence: settings.response_pos_confidence.map(|p| p as usize),
            pos_explanation: settings.response_pos_explanation.map(|p| p as usize),
            categories: &categories,
            confidence: &confidence,
        };
        if let Some(classified) = answer::parse(&reply, &rules) {
            ctx.result.tags.insert(classified.tag.clone());
            ctx.result.llm_result = Some((
                classified.tag,
                classified.explanation.unwrap_or_default(),
            ));
            ctx.result.llm_bounds = Some((
                limits.spam_max_added as f32,
                limits.spam_max_subtracted as f32,
            ));
        }
    }
}
