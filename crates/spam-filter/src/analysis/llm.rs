/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The language model's opinion as one spam signal (AI spam classification
//! spec, AI-3, AI-4, AI-6, AI-9 to AI-13, AI-16). Any failure leaves the
//! message scored as if the classifier were off.

use crate::{
    SpamFilterContext, TextPart,
    modules::expression::{ScoreVariables, SpamFilterResolver, StringResolver},
};
use common::{
    Server,
    config::mailstore::spamfilter::{Location, SpamFilterAction},
    enterprise::llm::{AiModelExt, Call},
    expr::{Bump, if_block::BootstrapExprExt},
};
use inbuxa_features::ai::{answer, request};
use registry::{
    schema::{
        enums::{SPAM_AI_VARIABLE, SpamAiMode},
        prelude::{ExpressionContext, ObjectType, Property},
        structs::SpamAi,
    },
    types::id::ObjectId,
};
use std::{future::Future, time::Instant};
use store::registry::bootstrap::Bootstrap;
use types::id::Id;

pub trait SpamFilterAnalyzeLlm: Sync + Send {
    /// `scores` is the provisional score, for `x:SpamAi`'s condition.
    fn spam_filter_analyze_llm(
        &self,
        ctx: &mut SpamFilterContext<'_>,
        scores: ScoreVariables,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeLlm for Server {
    async fn spam_filter_analyze_llm(&self, ctx: &mut SpamFilterContext<'_>, scores: ScoreVariables) {
        // Read now, so a change applies to the next message (AI-18)
        let Ok(Some(SpamAi::Enable(settings))) =
            self.registry().object::<SpamAi>(Id::singleton()).await
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

        // inbuxa: 1.0's condition, on the provisional score. One that can't be
        // compiled sends nothing: it was meant to keep mail from the model.
        let mut bp = Bootstrap::new_uninitialized(self.registry().clone());
        let condition = bp.compile_expr(
            ObjectId::new(ObjectType::SpamAi, Id::singleton()),
            &ExpressionContext {
                expr: &settings.condition,
                default: None,
                property: Property::Condition,
                allowed_variables: SPAM_AI_VARIABLE,
                allowed_constants: &[],
            },
        );
        if !bp.errors.is_empty() {
            trc::event!(
                Registry(trc::RegistryEvent::BuildWarning),
                Details = "The AI spam classifier's condition can't be evaluated",
            );
            return;
        }
        if !condition.is_empty() {
            let mut arena = Bump::new();
            let resolver = SpamFilterResolver::new(
                &ctx.input,
                &ctx.output,
                &ctx.result.tags,
                &StringResolver(""),
                Location::BodyText,
            )
            .with_scores(scores);
            let run = self
                .eval_if::<bool, _>(&condition, &resolver, &mut arena, ctx.input.span_id)
                .await
                .unwrap_or(false);
            if !run {
                return;
            }
        }

        let limits = self.ai_limits().await;

        // AI-3: the subject and the message's text, nothing else
        let text = ctx
            .output
            .text_parts
            .iter()
            .filter_map(|part| match part {
                TextPart::Plain { text_body, .. } => Some(*text_body),
                TextPart::Html { text_body, .. } => Some(*text_body),
                TextPart::None => None,
            })
            .collect::<Vec<_>>()
            .join("\n\n");
        let max_bytes = match settings.max_input_chars {
            0 => limits.max_content_bytes as usize,
            chars => (limits.max_content_bytes as usize).min(chars as usize),
        };
        let nonce = request::nonce();
        let user = request::classification_text(&ctx.output.subject, &text, max_bytes, &nonce);
        let prompt_categories = settings
            .categories
            .iter()
            .map(|category| answer::PromptCategory {
                name: &category.name,
                description: &category.description,
                includes: category.includes.iter().map(String::as_str).collect(),
            })
            .collect::<Vec<_>>();
        let system = request::system_text(&answer::spam_ai_prompt(
            &settings.instructions,
            &prompt_categories,
            settings.explanation,
        ));
        let categories = settings
            .categories
            .iter()
            .map(|category| category.name.clone())
            .collect::<Vec<_>>();
        let confidence = answer::SPAM_AI_CONFIDENCE.map(String::from).to_vec();
        let rules = answer::spam_ai_rules(&categories, &confidence, settings.explanation);

        // inbuxa: 1.0's tiers: the next model is asked when this one is unsure
        // or names one of its escalation categories, all within the deadline
        let started = Instant::now();
        let deadline = settings.deadline.into_inner();
        let tiers = settings.tiers.iter().collect::<Vec<_>>();
        let mut verdict = None;
        for (position, tier) in tiers.iter().enumerate() {
            let Some(remaining) = deadline
                .checked_sub(started.elapsed())
                .filter(|remaining| !remaining.is_zero())
            else {
                break;
            };
            let Some(model) = self.ai_model_by_id(tier.model_id).await else {
                continue;
            };
            // AI-9: never longer than the ceiling, whatever the model's timeout
            let timeout = model
                .timeout()
                .min(limits.spam_call_ceiling.into_inner())
                .min(remaining);
            let Ok(reply) = self
                .ai_call(Call {
                    model_id: tier.model_id,
                    model: &model,
                    account_id: None,
                    system: Some(&system),
                    user: &user,
                    temperature: model.temperature(),
                    max_tokens: request::CLASSIFY_MAX_TOKENS,
                    timeout,
                    explain: None,
                    stream: None,
                })
                .await
            else {
                continue;
            };
            let Some(classified) = answer::parse(&reply, &rules) else {
                continue;
            };
            let probability = answer::verbal_probability(
                classified.confidence.as_deref().unwrap_or_default(),
                settings.verbal_high.into_inner(),
                settings.verbal_medium.into_inner(),
                settings.verbal_low.into_inner(),
            );
            let escalate = probability < tier.escalate_below.into_inner()
                || tier
                    .escalate_on
                    .iter()
                    .any(|category| category.eq_ignore_ascii_case(&classified.category));
            verdict = Some((classified, probability));
            if !escalate || position + 1 == tiers.len() {
                break;
            }
        }
        let Some((classified, probability)) = verdict else {
            return;
        };

        // An unsure verdict leaves no tag
        if probability < settings.uncertain_below.into_inner() {
            return;
        }
        let tag = answer::bucket_tag(
            &classified.category,
            probability,
            settings.bucket_high.into_inner(),
            settings.bucket_medium.into_inner(),
        );
        // AI-15: sanitized, encoded and folded
        if settings.add_header {
            ctx.result.ai.header = Some(answer::header(
                &tag,
                classified.explanation.as_deref().filter(|e| !e.is_empty()),
            ));
        }
        // inbuxa: 1.0's shadow mode logs the verdict without scoring it
        if settings.mode == SpamAiMode::Shadow {
            trc::event!(
                Ai(trc::AiEvent::LlmResponse),
                SpanId = ctx.input.span_id,
                Result = tag,
                Reason = "Shadow mode: not scored",
            );
            return;
        }
        ctx.result.tags.insert(tag.clone().into());
        ctx.result.llm_result = Some((tag, classified.explanation.unwrap_or_default()));
        ctx.result.llm_bounds = Some((
            limits.spam_max_added as f32,
            limits.spam_max_subtracted as f32,
        ));
    }
}
