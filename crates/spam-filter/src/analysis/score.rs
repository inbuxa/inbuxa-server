/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    SpamFilterContext, SpamFilterResult,
    analysis::{
        classifier::SpamFilterAnalyzeClassify,
        date::SpamFilterAnalyzeDate,
        dmarc::SpamFilterAnalyzeDmarc,
        domain::SpamFilterAnalyzeDomain,
        ehlo::SpamFilterAnalyzeEhlo,
        from::SpamFilterAnalyzeFrom,
        headers::SpamFilterAnalyzeHeaders,
        html::SpamFilterAnalyzeHtml,
        ip::SpamFilterAnalyzeIp,
        messageid::SpamFilterAnalyzeMid,
        mime::SpamFilterAnalyzeMime,
        pyzor::SpamFilterAnalyzePyzor,
        received::SpamFilterAnalyzeReceived,
        recipient::SpamFilterAnalyzeRecipient,
        replyto::SpamFilterAnalyzeReplyTo,
        rules::{RuleStage, SpamFilterAnalyzeRules},
        subject::SpamFilterAnalyzeSubject,
        url::SpamFilterAnalyzeUrl,
    },
};
use common::{
    Server,
    config::mailstore::spamfilter::{ClassifierConfig, SpamFilterAction, SpamFilterScoreConfig},
};
use compact_str::CompactString;
use std::{fmt::Write, future::Future, vec};

use utils::glob::GlobMap;

pub trait SpamFilterAnalyzeScore: Sync + Send {
    fn spam_filter_finalize(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = SpamFilterAction<SpamFilterScore>> + Send;

    fn spam_filter_classify(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = SpamFilterAction<SpamFilterScore>> + Send;
}

#[derive(Debug, Default)]
pub struct SpamFilterScore {
    pub results: Vec<f32>,
    pub headers: String,
    pub train_spam: Option<bool>,
    pub score: f32,
    pub is_spam: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreDecision {
    Reject,
    Discard,
}

#[derive(Debug, Clone)]
pub struct ScoreAccumulator {
    entries: Vec<(CompactString, f32)>,
    tag_score: f32,
    header_len: usize,
    is_spam_trap: bool,
    rbl_count: u32,
    decision: Option<ScoreDecision>,
    probability: Option<f32>,
    probability_entry: Option<(&'static str, f32)>,
}

const HEADER_BASE_LEN: usize = 60;
const HEADER_TAG_OVERHEAD: usize = 14;
const EXTRA_ENTRIES: usize = 8;

impl ScoreAccumulator {
    pub fn new(result: &SpamFilterResult, scores: &GlobMap<SpamFilterAction<f32>>) -> Self {
        let probability = result.classifier_probability();
        let probability_tag = probability.map(|probability| probability.spam_tag());
        let mut acc = ScoreAccumulator {
            entries: Vec::with_capacity(result.tags.len() + EXTRA_ENTRIES),
            tag_score: 0.0,
            header_len: HEADER_BASE_LEN,
            is_spam_trap: false,
            rbl_count: 0,
            decision: None,
            probability,
            probability_entry: probability_tag.map(|tag| (tag, score_of(scores, tag))),
        };
        for tag in &result.tags {
            if probability_tag.is_some_and(|probability_tag| tag == probability_tag) {
                continue;
            }
            if !acc.add(tag, scores) {
                break;
            }
        }
        acc
    }

    pub fn add(&mut self, tag: &CompactString, scores: &GlobMap<SpamFilterAction<f32>>) -> bool {
        if self.decision.is_some() {
            return false;
        }
        let score = match scores.get(tag) {
            Some(SpamFilterAction::Allow(score)) => *score,
            Some(SpamFilterAction::Discard) => {
                self.decision = Some(ScoreDecision::Discard);
                return false;
            }
            Some(SpamFilterAction::Reject) => {
                self.decision = Some(ScoreDecision::Reject);
                return false;
            }
            None | Some(SpamFilterAction::Disabled) => 0.0,
        };
        if tag == "SPAM_TRAP" {
            self.is_spam_trap = true;
        } else if score > 1.0 && tag.starts_with("RBL_") {
            self.rbl_count += 1;
        }
        self.tag_score += score;
        self.header_len += tag.len() + HEADER_TAG_OVERHEAD;
        if score != 0.0 || !tag.starts_with("X_") {
            self.entries.push((tag.clone(), score));
        }
        true
    }

    pub fn decision(&self) -> Option<ScoreDecision> {
        self.decision
    }

    pub fn score(&self) -> f32 {
        self.tag_score + self.probability_entry.map_or(0.0, |(_, score)| score)
    }

    pub fn probability(&self) -> Option<f32> {
        self.probability
    }
}

fn score_of(scores: &GlobMap<SpamFilterAction<f32>>, tag: &str) -> f32 {
    scores
        .get(tag)
        .and_then(|v| v.as_score())
        .copied()
        .unwrap_or_default()
}

impl SpamFilterAnalyzeScore for Server {
    async fn spam_filter_finalize(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> SpamFilterAction<SpamFilterScore> {
        let acc = ScoreAccumulator::new(&ctx.result, &self.core.spam.lists.scores);
        finalize(
            ctx,
            acc,
            &self.core.spam.lists.scores,
            &self.core.spam.scores,
            self.core.spam.classifier.as_ref(),
        )
    }

    async fn spam_filter_classify(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> SpamFilterAction<SpamFilterScore> {
        // IP address analysis
        self.spam_filter_analyze_ip(ctx).await;

        // DMARC/SPF/DKIM/ARC analysis
        self.spam_filter_analyze_dmarc(ctx).await;

        // EHLO hostname analysis
        self.spam_filter_analyze_ehlo(ctx).await;

        // Generic header analysis
        self.spam_filter_analyze_headers(ctx).await;

        // Received headers analysis
        self.spam_filter_analyze_received(ctx).await;

        // Message-ID analysis
        self.spam_filter_analyze_message_id(ctx).await;

        // Date header analysis
        self.spam_filter_analyze_date(ctx).await;

        // Subject analysis
        self.spam_filter_analyze_subject(ctx).await;

        // From and Envelope From analysis
        self.spam_filter_analyze_from(ctx).await;

        // Reply-To analysis
        self.spam_filter_analyze_reply_to(ctx).await;

        // Recipient analysis
        self.spam_filter_analyze_recipient(ctx).await;

        // E-mail and domain analysis
        self.spam_filter_analyze_domain(ctx).await;

        // URL analysis
        self.spam_filter_analyze_url(ctx).await;

        // MIME part analysis
        self.spam_filter_analyze_mime(ctx).await;

        // HTML content analysis
        self.spam_filter_analyze_html(ctx).await;

        // Spam trap
        self.spam_filter_analyze_spam_trap(ctx).await;

        // Pyzor checks
        self.spam_filter_analyze_pyzor(ctx).await;

        // Model classification
        self.spam_filter_analyze_classify(ctx).await;
        if let Some(probability) = ctx.result.classifier_probability() {
            ctx.result
                .tags
                .insert(CompactString::const_new(probability.spam_tag()));
        }

        // User-defined rules that do not depend on AI tags
        self.spam_filter_analyze_rule_set(ctx, RuleStage::BeforeAi, None)
            .await;

        // Provisional score
        let scores = &self.core.spam.lists.scores;
        let mut acc = ScoreAccumulator::new(&ctx.result, scores);


        // User-defined rules that depend on AI tags
        if acc.decision().is_none() && !self.core.spam.rules.after_ai.is_empty() {
            let mut added = Vec::new();
            self.spam_filter_analyze_rule_set(ctx, RuleStage::AfterAi, Some(&mut added))
                .await;
            for tag in &added {
                if !acc.add(tag, scores) {
                    break;
                }
            }
        }

        // Final score calculation
        finalize(
            ctx,
            acc,
            scores,
            &self.core.spam.scores,
            self.core.spam.classifier.as_ref(),
        )
    }
}

pub fn finalize(
    ctx: &mut SpamFilterContext<'_>,
    acc: ScoreAccumulator,
    scores: &GlobMap<SpamFilterAction<f32>>,
    thresholds: &SpamFilterScoreConfig,
    classifier: Option<&ClassifierConfig>,
) -> SpamFilterAction<SpamFilterScore> {
    match acc.decision {
        Some(ScoreDecision::Reject) => return SpamFilterAction::Reject,
        Some(ScoreDecision::Discard) => return SpamFilterAction::Discard,
        None => {}
    }

    let ScoreAccumulator {
        mut entries,
        tag_score,
        header_len,
        is_spam_trap,
        rbl_count,
        probability,
        probability_entry,
        ..
    } = acc;
    ctx.result.score = tag_score;

    let mut final_score = tag_score;
    let mut user_results = vec![tag_score; ctx.input.env_rcpt_rewritten_to.len()];
    for (user_result, confidence) in user_results
        .iter_mut()
        .zip(ctx.result.classifier_confidence.iter())
    {
        if let Some(confidence) = confidence {
            *user_result = tag_score + score_of(scores, confidence.spam_tag());
        }
    }
    if let Some((tag, score)) = probability_entry {
        entries.push((CompactString::const_new(tag), score));
        final_score += score;
    }
    let avg_confidence = probability.unwrap_or_default();

    if thresholds.reject_threshold > 0.0 && final_score >= thresholds.reject_threshold {
        SpamFilterAction::Reject
    } else if thresholds.discard_threshold > 0.0 && final_score >= thresholds.discard_threshold {
        SpamFilterAction::Discard
    } else {
        let ai_header = ctx.result.ai.header.as_deref();
        let mut headers = String::with_capacity(header_len + 40 + ai_header.map_or(0, str::len));
        entries.sort_unstable_by(|a, b| a.1.total_cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        headers.push_str("X-Spam-Result: ");
        for (idx, (tag, score)) in entries.into_iter().enumerate() {
            if idx > 0 {
                headers.push_str(",\r\n\t");
            }
            headers.push_str(&tag);
            headers.push_str(" (");
            push_two_decimals(&mut headers, score);
            headers.push(')');
        }
        headers.push_str("\r\n");

        if let Some(ai_header) = ai_header {
            headers.push_str(ai_header);
        }

        let is_spam = final_score >= thresholds.spam_threshold;
        let class = if is_spam { "spam" } else { "ham" };

        headers.push_str("X-Spam-Score: ");
        headers.push_str(class);
        headers.push_str(", score=");
        push_two_decimals(&mut headers, final_score);
        if avg_confidence != 0.0 {
            headers.push_str(", avg_confidence=");
            push_two_decimals(&mut headers, avg_confidence);
        }
        headers.push_str("\r\n");

        // Autolearn SPAM
        let mut train_spam = None;
        if is_spam
            && classifier.is_some_and(|c| {
                (c.auto_learn_spam_trap && is_spam_trap)
                    || (c.auto_learn_spam_rbl_count > 0 && rbl_count >= c.auto_learn_spam_rbl_count)
            })
        {
            train_spam = Some(true);
        } else if let Some(ai_train) = ctx.result.ai.train_spam
            && ai_train == is_spam
            && classifier.is_some()
        {
            train_spam = Some(ai_train);
        }

        SpamFilterAction::Allow(SpamFilterScore {
            results: user_results,
            headers,
            train_spam,
            score: final_score,
            is_spam,
        })
    }
}

#[inline(always)]
pub(crate) fn push_two_decimals(out: &mut String, value: f32) {
    let scaled = (value.abs() as f64) * 100.0;
    if scaled < 1e15 {
        if value.is_sign_negative() {
            out.push('-');
        }
        let scaled = scaled.round_ties_even() as u64;
        let mut buf = [b'0'; 24];
        let mut pos = buf.len();
        let fraction = (scaled % 100) as usize;
        pos -= 1;
        buf[pos] = b'0' + (fraction % 10) as u8;
        pos -= 1;
        buf[pos] = b'0' + (fraction / 10) as u8;
        pos -= 1;
        buf[pos] = b'.';
        let mut integral = scaled / 100;
        loop {
            pos -= 1;
            buf[pos] = b'0' + (integral % 10) as u8;
            integral /= 10;
            if integral == 0 {
                break;
            }
        }
        if let Ok(text) = std::str::from_utf8(&buf[pos..]) {
            out.push_str(text);
        }
    } else {
        push_two_decimals_cold(out, value);
    }
}

#[inline(never)]
fn push_two_decimals_cold(out: &mut String, value: f32) {
    let _ = write!(out, "{value:.2}");
}

pub trait ConfidenceStore {
    fn spam_tag(&self) -> &'static str;
}

impl ConfidenceStore for f32 {
    fn spam_tag(&self) -> &'static str {
        match *self {
            p if p < 0.15 => "PROB_HAM_HIGH",
            p if p < 0.25 => "PROB_HAM_MEDIUM",
            p if p < 0.40 => "PROB_HAM_LOW",
            p if p < 0.60 => "PROB_SPAM_UNCERTAIN",
            p if p < 0.75 => "PROB_SPAM_LOW",
            p if p < 0.85 => "PROB_SPAM_MEDIUM",
            p => {
                if p.is_finite() {
                    "PROB_SPAM_HIGH"
                } else {
                    "PROB_SPAM_UNCERTAIN"
                }
            }
        }
    }
}

