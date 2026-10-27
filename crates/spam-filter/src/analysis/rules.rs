/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    SpamFilterContext, SpamFilterInput, SpamFilterOutput, TextPart,
    modules::expression::{
        EmailHeader, HEADER_NAME_INLINE, ScoreVariables, SpamFilterResolver, StringResolver,
        lower_header_name,
    },
};
use common::{
    Server,
    config::mailstore::spamfilter::{IpResolver, Location, SpamFilterRuleSet},
    expr::{Bump, functions::ResolveVariable, guard::Selection},
};
use compact_str::CompactString;
use std::future::Future;
use store::ahash::AHashSet;

pub trait SpamFilterAnalyzeRules: Sync + Send {
    fn spam_filter_analyze_rules(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;

    fn spam_filter_analyze_rule_set(
        &self,
        ctx: &mut SpamFilterContext<'_>,
        stage: RuleStage,
        added: Option<&mut Vec<CompactString>>,
    ) -> impl Future<Output = ()> + Send;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleStage {
    BeforeAi,
    AfterAi,
}

struct RulePass<'x> {
    server: &'x Server,
    input: &'x SpamFilterInput<'x>,
    output: &'x SpamFilterOutput<'x>,
    scores: ScoreVariables,
}

impl SpamFilterAnalyzeRules for Server {
    async fn spam_filter_analyze_rules(&self, ctx: &mut SpamFilterContext<'_>) {
        self.spam_filter_analyze_rule_set(ctx, RuleStage::BeforeAi, None)
            .await;
        self.spam_filter_analyze_rule_set(ctx, RuleStage::AfterAi, None)
            .await;
    }

    async fn spam_filter_analyze_rule_set(
        &self,
        ctx: &mut SpamFilterContext<'_>,
        stage: RuleStage,
        mut added: Option<&mut Vec<CompactString>>,
    ) {
        let rules: &SpamFilterRuleSet = match stage {
            RuleStage::BeforeAi => &self.core.spam.rules.before_ai,
            RuleStage::AfterAi => &self.core.spam.rules.after_ai,
        };
        if rules.is_empty() {
            return;
        }
        let mut arena = std::mem::take(ctx.arena.get_mut());
        let pass = RulePass {
            server: self,
            input: &ctx.input,
            output: &ctx.output,
            scores: ScoreVariables::for_rules(ctx.result.classifier_probability()),
        };
        let tags = &mut ctx.result.tags;

        if !rules.url.is_empty() {
            for url in &ctx.output.urls {
                pass.eval(
                    rules.url.select(url.location.as_str()),
                    &url.element,
                    url.location,
                    tags,
                    &mut added,
                    &mut arena,
                )
                .await;
            }
        }

        if !rules.domain.is_empty() {
            for domain in &ctx.output.domains {
                pass.eval(
                    rules.domain.select(domain.location.as_str()),
                    &StringResolver(domain.element.as_str()),
                    domain.location,
                    tags,
                    &mut added,
                    &mut arena,
                )
                .await;
            }
        }

        if !rules.email.is_empty() {
            for email in &ctx.output.emails {
                pass.eval(
                    rules.email.select(email.location.as_str()),
                    &email.element,
                    email.location,
                    tags,
                    &mut added,
                    &mut arena,
                )
                .await;
            }

            for (rcpt, location) in [
                (&ctx.output.recipients_to, Location::HeaderTo),
                (&ctx.output.recipients_cc, Location::HeaderCc),
                (&ctx.output.recipients_bcc, Location::HeaderBcc),
            ] {
                let selection = rules.email.select(location.as_str());
                for email in rcpt {
                    pass.eval(selection, email, location, tags, &mut added, &mut arena)
                        .await;
                }
            }
        }

        if !rules.ip.is_empty() {
            for ip in &ctx.output.ips {
                pass.eval(
                    rules.ip.select(ip.location.as_str()),
                    &IpResolver::new(ip.element),
                    ip.location,
                    tags,
                    &mut added,
                    &mut arena,
                )
                .await;
            }
        }

        if !rules.header.is_empty() {
            let mut inline = [0u8; HEADER_NAME_INLINE];
            let mut header_arena = Bump::new();
            for header in ctx.input.message.headers() {
                header_arena.reset();
                let name = header.raw_name();
                let name_lower = lower_header_name(name, &mut inline, &header_arena);
                let selection = rules.header.select(name_lower);
                if selection.is_empty() {
                    continue;
                }
                let header = EmailHeader {
                    header,
                    name,
                    name_lower,
                };
                pass.eval(
                    selection,
                    &header,
                    Location::BodyText,
                    tags,
                    &mut added,
                    &mut arena,
                )
                .await;
            }
        }

        if !rules.body.is_empty() {
            for (idx, part) in ctx.output.text_parts.iter().enumerate() {
                let text = match part {
                    TextPart::Plain { text_body, .. } => *text_body,
                    TextPart::Html { text_body, .. } => *text_body,
                    TextPart::None => continue,
                };
                let idx = idx as u32;
                let location = if ctx.input.is_text_body(idx) {
                    Location::BodyText
                } else if ctx.input.is_html_body(idx) {
                    Location::BodyHtml
                } else {
                    Location::Attachment
                };
                pass.eval(
                    rules.body.select(location.as_str()),
                    &StringResolver(text),
                    location,
                    tags,
                    &mut added,
                    &mut arena,
                )
                .await;
            }
        }

        if !rules.any.is_empty() {
            pass.eval(
                rules.any.all(),
                &StringResolver(""),
                Location::BodyText,
                tags,
                &mut added,
                &mut arena,
            )
            .await;
        }

        *ctx.arena.get_mut() = arena;
    }
}

impl RulePass<'_> {
    async fn eval<T: ResolveVariable>(
        &self,
        selection: Selection<'_>,
        item: &T,
        location: Location,
        tags: &mut AHashSet<CompactString>,
        added: &mut Option<&mut Vec<CompactString>>,
        arena: &mut Bump,
    ) {
        for rule in selection.iter() {
            if let Some(tag) = self
                .server
                .eval_if::<CompactString, _>(
                    rule,
                    &SpamFilterResolver::new(self.input, self.output, tags, item, location)
                        .with_scores(self.scores),
                    arena,
                    self.input.span_id,
                )
                .await
            {
                if let Some(added) = added.as_deref_mut()
                    && !tags.contains(&tag)
                {
                    added.push(tag.clone());
                }
                tags.insert(tag);
            }
        }
    }
}
