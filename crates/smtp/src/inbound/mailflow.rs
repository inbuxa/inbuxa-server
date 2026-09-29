/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: DLP at DATA (dlp-and-mail-flow-rules spec, §2.1, §2.4–§2.7).
//!
//! Runs after the DATA system script and before headers and DKIM signing,
//! on mail an authenticated sender submits over SMTP or JMAP. The rules and
//! the detectors are `inbuxa_features::mailflow`; this is the glue: build
//! what they look at from the message, apply the decision, record it.

use crate::core::{DlpRefusal, Session};
use common::network::SessionStream;
use inbuxa_features::{
    audit::{Action, Actor, Outcome, Record, Target},
    mailflow::{
        cache,
        engine::{
            Attachment, Content, Decision, Envelope, Outcome as RulesOutcome, Recipient, RuleRef,
        },
        extract::{self, Extracted, Limits},
        rewrite,
        rules::{Action as RuleAction, Kind},
    },
};
use mail_parser::{Message, MessageParser, MimeHeaders, PartType};
use std::{borrow::Cow, time::SystemTime};

/// How much text one message is read for; past it, the rest counts as
/// "can't be inspected" (§2.3).
const INSPECTION_LIMIT: usize = 10 * 1024 * 1024;

/// What the check decided.
pub enum Checked {
    /// Go on, with the message unchanged.
    Accept,
    /// Go on, with a changed message (the override tag taken out, a
    /// disclaimer, headers, the subject) and envelope.
    Changed {
        message: Option<Vec<u8>>,
        envelope: Vec<EnvelopeChange>,
    },
    /// Refuse, with this SMTP reply, and for a JMAP submission, why.
    Refuse(Vec<u8>, Option<DlpRefusal>),
}

/// What a transport rule changes about where a message goes.
pub enum EnvelopeChange {
    AddRecipient(String),
    Redirect(Vec<String>),
    Route(String),
}

/// `[override: reason]` at the start of a subject: the reason, and the
/// subject without it.
pub fn override_tag(subject: &str) -> Option<(String, String)> {
    let trimmed = subject.trim_start();
    let head = trimmed.get(..10)?;
    if !head.eq_ignore_ascii_case("[override:") {
        return None;
    }
    let close = trimmed.find(']')?;
    let reason = trimmed[10..close].trim();
    if reason.is_empty() {
        return None;
    }
    Some((
        reason.chars().take(500).collect(),
        trimmed[close + 1..].trim_start().to_string(),
    ))
}

/// One line of an SMTP reply: no line breaks, a sane length.
fn reply_text(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(400)
        .collect()
}

fn notices(rules: &[RuleRef]) -> String {
    let mut seen = Vec::new();
    for rule in rules {
        let notice = reply_text(&rule.notice);
        if !seen.contains(&notice) {
            seen.push(notice);
        }
    }
    seen.join(" ")
}

fn refusal(blocked: bool, rules: &[RuleRef]) -> DlpRefusal {
    DlpRefusal {
        blocked,
        rules: rules
            .iter()
            .map(|r| (r.name.clone(), r.notice.clone()))
            .collect(),
    }
}

/// A message and the messages attached to it, one level down.
fn collect<'x>(message: &'x Message<'x>, content: &mut Content<'x>, budget: &mut usize, depth: u8) {
    let add = |text: Cow<'x, str>, content: &mut Content<'x>, budget: &mut usize| {
        if *budget == 0 {
            content.truncated = true;
            return;
        }
        if text.len() > *budget {
            let mut cut = *budget;
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            content.bodies.push(Cow::Owned(text[..cut].to_string()));
            content.truncated = true;
            *budget = 0;
        } else {
            *budget -= text.len();
            content.bodies.push(text);
        }
    };
    // The text version of each body (an HTML-only one converted), not both
    // versions of the same alternative, so words aren't counted twice
    for part in message.text_bodies() {
        match &part.body {
            PartType::Text(text) => add(Cow::Borrowed(text.as_ref()), content, budget),
            PartType::Html(html) => add(
                Cow::Owned(mail_parser::decoders::html::html_to_text(html)),
                content,
                budget,
            ),
            _ => {}
        }
    }
    for part in message.attachments() {
        if let (Some(inner), true) = (part.message(), depth == 0) {
            if let Some(subject) = inner.subject() {
                add(Cow::Borrowed(subject), content, budget);
            }
            collect(inner, content, budget, depth + 1);
            continue;
        }
        let content_type = part
            .content_type()
            .map(|ct| match ct.subtype() {
                Some(sub) => format!("{}/{}", ct.ctype(), sub),
                None => ct.ctype().to_string(),
            })
            .unwrap_or_default();
        let bytes = part.contents();
        let mut extracted = extract::extract(
            &content_type,
            part.attachment_name(),
            bytes,
            &Limits::default(),
        );
        if let Extracted::Text(text) = &extracted {
            if text.len() > *budget {
                extracted = Extracted::NotInspectable(extract::Why::TooLarge);
            } else {
                *budget -= text.len();
            }
        }
        content.attachments.push(Attachment {
            name: part.attachment_name(),
            content_type: content_type.into(),
            size: bytes.len() as u64,
            extracted,
        });
    }
}

impl<T: SessionStream> Session<T> {
    /// DLP on an outgoing message (§2.4). `message` is what the DATA stage
    /// has so far (the script's replacement, if it made one).
    pub async fn check_mail_rules(&self, message: &[u8]) -> Checked {
        // Outgoing: an authenticated sender. DLP rules check outgoing mail
        // only (settled); transport rules may check either
        let sender = self
            .data
            .authenticated_as
            .as_ref()
            .map(|s| (s.account_id, s.account.clone()));
        let outgoing = sender.is_some();
        let rules = match cache::compiled(self.server.store()).await {
            Ok(rules) => rules,
            Err(err) => {
                trc::error!(
                    err.span_id(self.data.session_id)
                        .caused_by(trc::location!())
                        .details("Failed to load mail rules")
                );
                // Fail closed: a message nobody could check doesn't leave
                return Checked::Refuse(
                    b"451 4.3.0 This message couldn't be checked against the server's rules. Try again later.\r\n"
                        .to_vec(),
                    None,
                );
            }
        };
        if !rules.applies_to(outgoing) {
            return Checked::Accept;
        }

        let parsed = MessageParser::new().parse(message);
        let subject = parsed
            .as_ref()
            .and_then(|m| m.subject())
            .unwrap_or_default();
        let jmap_override = self.data.dlp_override.clone();
        // Only a sender of ours can override
        let tag = if outgoing {
            override_tag(subject)
        } else {
            None
        };
        let checked_subject = tag.as_ref().map_or(subject, |(_, rest)| rest.as_str());

        let mut content = Content {
            subject: checked_subject,
            size: message.len() as u64,
            ..Default::default()
        };
        let mut budget = INSPECTION_LIMIT;
        match &parsed {
            Some(parsed) => {
                content.headers = parsed
                    .headers()
                    .iter()
                    .filter_map(|h| h.value.as_text().map(|v| (h.name.as_str(), v)))
                    .collect();
                collect(parsed, &mut content, &mut budget, 0);
            }
            // Nothing a rule could read: say so, rather than pass it
            None => content.truncated = true,
        }
        let mut recipient_groups = Vec::with_capacity(self.data.rcpt_to.len());
        for rcpt in &self.data.rcpt_to {
            let local = self
                .server
                .domain(&rcpt.domain)
                .await
                .ok()
                .flatten()
                .is_some();
            let groups = if local {
                match self
                    .server
                    .account_id_from_email(&rcpt.address_lcase, false)
                    .await
                {
                    Ok(Some(id)) => self
                        .server
                        .account(id)
                        .await
                        .map(|a| a.id_member_of.to_vec())
                        .unwrap_or_default(),
                    _ => Vec::new(),
                }
            } else {
                Vec::new()
            };
            recipient_groups.push((local, groups));
        }
        let sender_address = self
            .data
            .mail_from
            .as_ref()
            .map(|m| m.address_lcase.clone())
            .unwrap_or_default();
        let envelope = Envelope {
            outgoing,
            sender: &sender_address,
            sender_groups: sender
                .as_ref()
                .map_or(&[][..], |(_, a)| &a.id_member_of[..]),
            sender_tenant: sender.as_ref().and_then(|(_, a)| a.id_tenant),
            recipients: self
                .data
                .rcpt_to
                .iter()
                .zip(&recipient_groups)
                .map(|(rcpt, (local, groups))| Recipient {
                    address: &rcpt.address_lcase,
                    local: *local,
                    groups,
                })
                .collect(),
        };

        let outcome = rules.evaluate(&envelope, &content);
        let override_reason =
            jmap_override.or_else(|| tag.as_ref().map(|(reason, _)| reason.clone()));
        let decision = outcome.decision(override_reason.is_some());
        let mut domains: Vec<&str> = self
            .data
            .rcpt_to
            .iter()
            .map(|r| r.domain.as_str())
            .collect();
        domains.sort_unstable();
        domains.dedup();
        let domains = domains.join(", ");
        drop(envelope);

        if let Some((account_id, account)) = &sender {
            self.record_dlp(
                *account_id,
                account,
                &outcome,
                &decision,
                override_reason.as_deref(),
                &domains,
            )
            .await;
        }

        match decision {
            Decision::Block(rules) | Decision::Hold { rules, .. } => {
                // Hold for review is phase 3: until then a hold rule blocks,
                // rather than let the message through unreviewed
                let refusal = refusal(true, &rules);
                Checked::Refuse(format!("550 5.7.1 {}\r\n", notices(&rules)).into_bytes(), Some(refusal))
            }
            Decision::Warn(rules) => Checked::Refuse(
                format!(
                    "550 5.7.1 {} To send anyway, start the subject with [override: your reason]\r\n",
                    notices(&rules)
                )
                .into_bytes(),
                Some(refusal(false, &rules)),
            ),
            Decision::Pass => {
                // The tag was an instruction to the server, not part of the
                // subject: it doesn't go out
                let mut current: Option<Vec<u8>> =
                    tag.map(|(_, rest)| rewrite::set_subject(message, &rest));
                let mut changes = Vec::new();
                for matched in outcome.matched.iter().filter(|m| m.kind == Kind::Transport) {
                    for action in &matched.actions {
                        let now = current.as_deref().unwrap_or(message);
                        let next = match action {
                            RuleAction::AddDisclaimer { text, html, position } => {
                                rewrite::add_disclaimer(now, text, html.as_deref(), *position)
                            }
                            RuleAction::AddHeader { name, value } => Some(rewrite::add_header(now, name, value)),
                            RuleAction::RemoveHeader { name } => rewrite::remove_header(now, name),
                            RuleAction::PrefixSubject { text } => rewrite::prefix_subject(now, text),
                            RuleAction::AddRecipient { address } => {
                                changes.push(EnvelopeChange::AddRecipient(address.clone()));
                                None
                            }
                            RuleAction::Redirect { addresses } => {
                                changes.push(EnvelopeChange::Redirect(addresses.clone()));
                                None
                            }
                            RuleAction::Route { queue } => {
                                changes.push(EnvelopeChange::Route(queue.clone()));
                                None
                            }
                            RuleAction::Refuse { text } => {
                                self.record_transport(&sender, &matched.name, "refused", &domains).await;
                                return Checked::Refuse(
                                    format!("550 5.7.1 {}\r\n", reply_text(text)).into_bytes(),
                                    None,
                                );
                            }
                            RuleAction::Block { .. } | RuleAction::Warn { .. } | RuleAction::Hold { .. } => None,
                        };
                        if next.is_some() {
                            current = next;
                        }
                    }
                    // Where mail goes is recorded; wording and headers aren't,
                    // or a banner rule would write a record for every message
                    let routed: Vec<String> = matched
                        .actions
                        .iter()
                        .filter_map(|a| match a {
                            RuleAction::AddRecipient { address } => Some(format!("copied to {address}")),
                            RuleAction::Redirect { addresses } => Some(format!("redirected to {}", addresses.join(", "))),
                            RuleAction::Route { queue } => Some(format!("routed through {queue}")),
                            _ => None,
                        })
                        .collect();
                    if !routed.is_empty() {
                        self.record_transport(&sender, &matched.name, &routed.join(", "), &domains).await;
                    }
                }
                if current.is_none() && changes.is_empty() {
                    Checked::Accept
                } else {
                    Checked::Changed { message: current, envelope: changes }
                }
            }
        }
    }

    /// A transport rule that refused a message or changed where it goes
    /// (§2.7): who sent it (or the server, for incoming mail), the rule,
    /// what it did.
    async fn record_transport(
        &self,
        sender: &Option<(u32, std::sync::Arc<common::auth::AccountCache>)>,
        rule: &str,
        what: &str,
        domains: &str,
    ) {
        let (actor, account_id, tenant_id) = match sender {
            Some((id, account)) => (
                Actor::account(*id, account.name.to_string(), account.id_tenant),
                Some(*id),
                account.id_tenant,
            ),
            None => (Actor::system("mail-flow"), None, None),
        };
        let at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        self.server
            .audit_note(Record {
                at,
                actor,
                via: None,
                remote_ip: Some(self.data.remote_ip),
                action: Action::Create,
                target: Target {
                    kind: "message".into(),
                    id: None,
                    name: None,
                    account_id,
                    tenant_id,
                },
                changes: vec![],
                details: Some(format!("Mail flow rule \"{rule}\" {what}, to {domains}")),
                reason: None,
                outcome: if what == "refused" {
                    Outcome::refused("forbidden", None)
                } else {
                    Outcome::success()
                },
            })
            .await;
    }

    /// One audit record per message a DLP rule matched (§2.7): who sent it,
    /// where to, which rules and each detector's count, what happened, and
    /// an override's reason. Never the matched text.
    async fn record_dlp(
        &self,
        account_id: u32,
        account: &common::auth::AccountCache,
        outcome: &RulesOutcome,
        decision: &Decision,
        override_reason: Option<&str>,
        domains: &str,
    ) {
        let dlp: Vec<_> = outcome
            .matched
            .iter()
            .filter(|m| m.kind == Kind::Dlp)
            .collect();
        if dlp.is_empty() {
            return;
        }
        let rules = dlp
            .iter()
            .map(|m| {
                let counts = m
                    .counts
                    .iter()
                    .map(|(id, n)| format!("{id} {n}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                if counts.is_empty() {
                    format!("\"{}\"", m.name)
                } else {
                    format!("\"{}\" ({counts})", m.name)
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        let (what, outcome, reason) = match decision {
            Decision::Block(_) | Decision::Hold { .. } => {
                ("blocked", Outcome::refused("inbuxa:dlpBlocked", None), None)
            }
            Decision::Warn(_) => ("warned", Outcome::refused("inbuxa:dlpWarning", None), None),
            Decision::Pass => (
                "sent after a warning",
                Outcome::success(),
                override_reason.map(str::to_string),
            ),
        };
        let at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        self.server
            .audit_note(Record {
                at,
                actor: Actor::account(account_id, account.name.to_string(), account.id_tenant),
                via: None,
                remote_ip: Some(self.data.remote_ip),
                action: Action::Create,
                target: Target {
                    kind: "message".into(),
                    id: None,
                    name: None,
                    account_id: Some(account_id),
                    tenant_id: account.id_tenant,
                },
                changes: vec![],
                details: Some(format!("DLP {what}, to {domains}: {rules}")),
                reason,
                outcome,
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::override_tag;

    #[test]
    fn override_tags() {
        assert_eq!(
            override_tag("[override: client asked for it] Card details"),
            Some(("client asked for it".into(), "Card details".into()))
        );
        assert_eq!(
            override_tag("  [OVERRIDE:yes]x"),
            Some(("yes".into(), "x".into()))
        );
        assert_eq!(override_tag("[override: ] x"), None);
        assert_eq!(override_tag("Re: [override: no] x"), None);
        assert_eq!(override_tag("[override: unclosed"), None);
        assert_eq!(override_tag(""), None);
    }
}
