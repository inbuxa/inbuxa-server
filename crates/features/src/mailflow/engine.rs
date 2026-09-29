/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Evaluating rules against a message (§2.1–§2.4). Rules are compiled once,
//! when they change: word lists become automata, patterns regexes. A message
//! is then checked against every enabled rule in order; each detector runs
//! at most once per message, and only when some rule asks for it.
//!
//! Pure: the caller parses the message, extracts attachment text
//! ([`super::extract`]) and knows the sender's groups and tenant. What comes
//! back is which rules matched, with each detector's count, and what DLP
//! decided; the matched text itself never leaves here (§2.7).

use super::{
    detectors::{self, Findings},
    extract::Extracted,
    rules::{Action, Condition, Direction, Kind, Rule},
    words::{Pattern, WordList},
};
use ahash::AHashMap;
use std::borrow::Cow;

/// Who sent a message, and to whom.
#[derive(Debug, Clone, Default)]
pub struct Envelope<'a> {
    /// Outgoing (an authenticated sender) or incoming.
    pub outgoing: bool,
    pub sender: &'a str,
    pub sender_groups: &'a [u32],
    pub sender_tenant: Option<u32>,
    pub recipients: Vec<Recipient<'a>>,
}

#[derive(Debug, Clone, Default)]
pub struct Recipient<'a> {
    pub address: &'a str,
    /// At a domain this server hosts.
    pub local: bool,
    pub groups: &'a [u32],
}

#[derive(Debug, Clone)]
pub struct Attachment<'a> {
    pub name: Option<&'a str>,
    /// Declared type, or detected where the caller knows better.
    pub content_type: Cow<'a, str>,
    pub size: u64,
    pub extracted: Extracted,
}

/// What rules look at.
#[derive(Debug, Clone, Default)]
pub struct Content<'a> {
    pub subject: &'a str,
    /// Each text and HTML part, as text.
    pub bodies: Vec<Cow<'a, str>>,
    pub headers: Vec<(&'a str, &'a str)>,
    pub attachments: Vec<Attachment<'a>>,
    pub size: u64,
    /// Text past the inspection limit wasn't read.
    pub truncated: bool,
}

impl Content<'_> {
    fn texts(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.subject)
            .chain(self.bodies.iter().map(|b| b.as_ref()))
            .chain(self.attachments.iter().filter_map(|a| match &a.extracted {
                Extracted::Text(text) => Some(text.as_str()),
                _ => None,
            }))
    }

    fn cant_be_inspected(&self) -> bool {
        self.truncated
            || self
                .attachments
                .iter()
                .any(|a| matches!(a.extracted, Extracted::NotInspectable(_)))
    }
}

enum Check {
    Plain(Condition),
    Words(WordList, u32),
    Pattern(Pattern, u32),
    Header {
        name: String,
        contains: Option<String>,
        matches: Option<Pattern>,
    },
    AttachmentName(Pattern),
}

struct CompiledRule {
    rule: Rule,
    conditions: Vec<Check>,
    exceptions: Vec<Check>,
}

/// The enabled rules, ready to run.
pub struct Compiled {
    rules: Vec<CompiledRule>,
}

/// A rule reference, for notices and the audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRef {
    pub id: u32,
    pub name: String,
    pub notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub rule_id: u32,
    pub name: String,
    pub kind: Kind,
    pub actions: Vec<Action>,
    /// Each detector (or `words`, `pattern`) that counted, and its count.
    pub counts: Vec<(String, usize)>,
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub matched: Vec<Match>,
    pub blocks: Vec<RuleRef>,
    pub holds: Vec<(RuleRef, bool)>,
    pub warns: Vec<RuleRef>,
}

/// What DLP decided, strictest first (§2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Pass,
    Block(Vec<RuleRef>),
    Hold {
        rules: Vec<RuleRef>,
        notify_sender: bool,
    },
    Warn(Vec<RuleRef>),
}

impl Outcome {
    /// Block beats hold beats warn. An override (§2.5) answers the warnings
    /// only: a block or hold still applies.
    pub fn decision(&self, overridden: bool) -> Decision {
        if !self.blocks.is_empty() {
            Decision::Block(self.blocks.clone())
        } else if !self.holds.is_empty() {
            Decision::Hold {
                rules: self.holds.iter().map(|(r, _)| r.clone()).collect(),
                notify_sender: self.holds.iter().any(|(_, notify)| *notify),
            }
        } else if !self.warns.is_empty() && !overridden {
            Decision::Warn(self.warns.clone())
        } else {
            Decision::Pass
        }
    }
}

fn compile_check(condition: &Condition) -> Result<Check, String> {
    Ok(match condition {
        Condition::Words { words, at_least } => Check::Words(WordList::new(words)?, *at_least),
        Condition::Pattern { pattern, at_least } => {
            Check::Pattern(Pattern::new(pattern)?, *at_least)
        }
        Condition::Header {
            name,
            contains,
            matches,
        } => Check::Header {
            name: name.to_ascii_lowercase(),
            contains: contains.as_ref().map(|c| c.to_lowercase()),
            matches: matches.as_deref().map(Pattern::new).transpose()?,
        },
        Condition::AttachmentName { pattern } => Check::AttachmentName(Pattern::new(pattern)?),
        other => Check::Plain(other.clone()),
    })
}

impl Compiled {
    /// Compiles the enabled rules; one that no longer compiles (a detector
    /// renamed since it was saved) is skipped and named in the second list.
    pub fn new(rules: &[Rule]) -> (Self, Vec<(u32, String)>) {
        let mut compiled = Vec::new();
        let mut skipped = Vec::new();
        for rule in rules.iter().filter(|r| r.enabled) {
            let result = rule.validate().map_err(|e| e.reason).and_then(|_| {
                Ok(CompiledRule {
                    rule: rule.clone(),
                    conditions: rule
                        .conditions
                        .iter()
                        .map(compile_check)
                        .collect::<Result<_, _>>()?,
                    exceptions: rule
                        .exceptions
                        .iter()
                        .map(compile_check)
                        .collect::<Result<_, _>>()?,
                })
            });
            match result {
                Ok(c) => compiled.push(c),
                Err(reason) => skipped.push((rule.id, reason)),
            }
        }
        compiled.sort_by_key(|c| (c.rule.priority, c.rule.id));
        (Self { rules: compiled }, skipped)
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Whether any rule could apply to mail going this way, so a caller can
    /// skip parsing when none can.
    pub fn applies_to(&self, outgoing: bool) -> bool {
        self.rules
            .iter()
            .any(|c| direction_matches(c.rule.direction, outgoing))
    }

    pub fn evaluate(&self, envelope: &Envelope<'_>, content: &Content<'_>) -> Outcome {
        let mut state = State {
            content,
            detected: AHashMap::new(),
        };
        let mut outcome = Outcome::default();
        for compiled in &self.rules {
            let rule = &compiled.rule;
            if !direction_matches(rule.direction, envelope.outgoing) {
                continue;
            }
            let mut counts = Vec::new();
            let all_match = compiled
                .conditions
                .iter()
                .all(|check| state.check(check, envelope, &mut counts));
            if !all_match {
                continue;
            }
            let mut ignored = Vec::new();
            if compiled
                .exceptions
                .iter()
                .any(|check| state.check(check, envelope, &mut ignored))
            {
                continue;
            }
            for action in &rule.actions {
                let reference = |notice: &str| RuleRef {
                    id: rule.id,
                    name: rule.name.clone(),
                    notice: notice.to_string(),
                };
                match action {
                    Action::Block { notice } => outcome.blocks.push(reference(notice)),
                    Action::Hold {
                        notice,
                        notify_sender,
                    } => outcome.holds.push((reference(notice), *notify_sender)),
                    Action::Warn { notice } => outcome.warns.push(reference(notice)),
                    _ => {}
                }
            }
            outcome.matched.push(Match {
                rule_id: rule.id,
                name: rule.name.clone(),
                kind: rule.kind,
                actions: rule.actions.clone(),
                counts,
            });
            if rule.stop_processing {
                break;
            }
        }
        outcome
    }
}

fn direction_matches(direction: Direction, outgoing: bool) -> bool {
    match direction {
        Direction::Any => true,
        Direction::Outgoing => outgoing,
        Direction::Incoming => !outgoing,
    }
}

fn domain_of(address: &str) -> &str {
    address.rsplit_once('@').map_or("", |(_, d)| d)
}

fn in_list(value: &str, list: &[String]) -> bool {
    list.iter().any(|v| v.eq_ignore_ascii_case(value))
}

struct State<'c, 'a> {
    content: &'c Content<'a>,
    /// Each detector's count, run once per message.
    detected: AHashMap<&'static str, usize>,
}

impl State<'_, '_> {
    fn detector_count(&mut self, id: &str) -> usize {
        let Some(detector) = detectors::by_id(id) else {
            return 0;
        };
        if let Some(count) = self.detected.get(detector.id) {
            return *count;
        }
        let mut findings = Findings::default();
        for text in self.content.texts() {
            detector.find(text, &mut findings);
        }
        self.detected.insert(detector.id, findings.len());
        findings.len()
    }

    fn check(
        &mut self,
        check: &Check,
        envelope: &Envelope<'_>,
        counts: &mut Vec<(String, usize)>,
    ) -> bool {
        let content = self.content;
        match check {
            Check::Words(list, at_least) => {
                let n: usize = content.texts().map(|t| list.count(t)).sum();
                counts.push(("words".into(), n));
                n >= *at_least as usize
            }
            Check::Pattern(pattern, at_least) => {
                let n: usize = content.texts().map(|t| pattern.count(t)).sum();
                counts.push(("pattern".into(), n));
                n >= *at_least as usize
            }
            Check::Header {
                name,
                contains,
                matches,
            } => content
                .headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                .any(|(_, value)| match (contains, matches) {
                    (Some(needle), _) => value.to_lowercase().contains(needle.as_str()),
                    (_, Some(pattern)) => pattern.count(value) > 0,
                    _ => true,
                }),
            Check::AttachmentName(pattern) => content
                .attachments
                .iter()
                .any(|a| a.name.is_some_and(|n| pattern.count(n) > 0)),
            Check::Plain(condition) => match condition {
                Condition::SenderAddress { addresses } => in_list(envelope.sender, addresses),
                Condition::SenderDomain { domains } => in_list(domain_of(envelope.sender), domains),
                Condition::SenderGroup { groups } => {
                    envelope.sender_groups.iter().any(|g| groups.contains(g))
                }
                Condition::SenderTenant { tenants } => {
                    envelope.sender_tenant.is_some_and(|t| tenants.contains(&t))
                }
                Condition::RecipientAddress { addresses } => envelope
                    .recipients
                    .iter()
                    .any(|r| in_list(r.address, addresses)),
                Condition::RecipientDomain { domains } => envelope
                    .recipients
                    .iter()
                    .any(|r| in_list(domain_of(r.address), domains)),
                Condition::RecipientGroup { groups } => envelope
                    .recipients
                    .iter()
                    .any(|r| r.groups.iter().any(|g| groups.contains(g))),
                Condition::RecipientOutside => envelope.recipients.iter().any(|r| !r.local),
                Condition::AttachmentType { types } => content.attachments.iter().any(|a| {
                    let ct = a.content_type.to_ascii_lowercase();
                    types
                        .iter()
                        .any(|t| ct.starts_with(&t.to_ascii_lowercase()))
                }),
                Condition::AttachmentExtension { extensions } => {
                    content.attachments.iter().any(|a| {
                        a.name
                            .and_then(|n| n.rsplit_once('.'))
                            .is_some_and(|(_, ext)| {
                                extensions
                                    .iter()
                                    .any(|e| e.trim_start_matches('.').eq_ignore_ascii_case(ext))
                            })
                    })
                }
                Condition::AttachmentSizeOver { bytes } => {
                    content.attachments.iter().any(|a| a.size > *bytes)
                }
                Condition::AttachmentCountOver { count } => {
                    content.attachments.len() > *count as usize
                }
                Condition::CantBeInspected => content.cant_be_inspected(),
                Condition::MessageSizeOver { bytes } => content.size > *bytes,
                Condition::Detected { detectors } => {
                    let mut any = false;
                    for d in detectors {
                        let n = self.detector_count(&d.id);
                        counts.push((d.id.clone(), n));
                        any |= n >= d.at_least as usize;
                    }
                    any
                }
                // Compiled into their own checks
                Condition::Words { .. }
                | Condition::Pattern { .. }
                | Condition::Header { .. }
                | Condition::AttachmentName { .. } => false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailflow::{
        extract::Why,
        rules::{DetectorMin, Position},
    };

    fn rule(id: u32, kind: Kind, conditions: Vec<Condition>, action: Action) -> Rule {
        Rule {
            id,
            name: format!("rule {id}"),
            description: String::new(),
            kind,
            enabled: true,
            priority: id as i32,
            direction: if kind == Kind::Dlp {
                Direction::Outgoing
            } else {
                Direction::Any
            },
            conditions,
            exceptions: vec![],
            actions: vec![action],
            stop_processing: false,
            created_by: String::new(),
            created_at: 0,
            updated_at: 0,
        }
    }

    fn envelope(outside: bool) -> Envelope<'static> {
        Envelope {
            outgoing: true,
            sender: "dana@example.com",
            sender_groups: &[7],
            sender_tenant: None,
            recipients: vec![Recipient {
                address: if outside {
                    "x@elsewhere.org"
                } else {
                    "y@example.com"
                },
                local: !outside,
                groups: &[],
            }],
        }
    }

    fn cards(n: usize) -> Content<'static> {
        let body: String = [
            "4242 4242 4242 4242",
            "5555-5555-5555-4444",
            "378282246310005",
            "6011111111111117",
            "3566002020360505",
        ]
        .iter()
        .take(n)
        .map(|c| format!("card {c}\n"))
        .collect();
        Content {
            subject: "Numbers",
            bodies: vec![body.into()],
            ..Default::default()
        }
    }

    fn five_cards_outside(action: Action) -> Rule {
        rule(
            1,
            Kind::Dlp,
            vec![
                Condition::RecipientOutside,
                Condition::Detected {
                    detectors: vec![DetectorMin {
                        id: "payment-card".into(),
                        at_least: 5,
                    }],
                },
            ],
            action,
        )
    }

    #[test]
    fn detector_threshold_and_recipients() {
        let (rules, skipped) = Compiled::new(&[five_cards_outside(Action::Hold {
            notice: "Held".into(),
            notify_sender: true,
        })]);
        assert!(skipped.is_empty());
        let outcome = rules.evaluate(&envelope(true), &cards(5));
        assert_eq!(
            outcome.matched[0].counts,
            vec![("payment-card".to_string(), 5)]
        );
        assert!(matches!(
            outcome.decision(false),
            Decision::Hold {
                notify_sender: true,
                ..
            }
        ));
        // Four cards, or everyone inside: nothing
        assert_eq!(
            rules.evaluate(&envelope(true), &cards(4)).decision(false),
            Decision::Pass
        );
        assert_eq!(
            rules.evaluate(&envelope(false), &cards(5)).decision(false),
            Decision::Pass
        );
    }

    #[test]
    fn strictest_wins_and_override_answers_warnings_only() {
        let warn = five_cards_outside(Action::Warn {
            notice: "Sure?".into(),
        });
        let mut block = five_cards_outside(Action::Block {
            notice: "No".into(),
        });
        block.id = 2;
        let (rules, _) = Compiled::new(&[warn.clone(), block]);
        let outcome = rules.evaluate(&envelope(true), &cards(5));
        assert!(matches!(outcome.decision(true), Decision::Block(_)));
        let (rules, _) = Compiled::new(&[warn]);
        let outcome = rules.evaluate(&envelope(true), &cards(5));
        assert!(matches!(outcome.decision(false), Decision::Warn(ref w) if w[0].notice == "Sure?"));
        assert_eq!(outcome.decision(true), Decision::Pass);
    }

    #[test]
    fn exceptions_order_and_stop_processing() {
        let disclaimer = |id| {
            rule(
                id,
                Kind::Transport,
                vec![Condition::RecipientOutside],
                Action::AddDisclaimer {
                    text: "t".into(),
                    html: None,
                    position: Position::Bottom,
                },
            )
        };
        let mut first = disclaimer(1);
        first.stop_processing = true;
        let (rules, _) = Compiled::new(&[disclaimer(2), first.clone()]);
        let outcome = rules.evaluate(&envelope(true), &cards(0));
        assert_eq!(
            outcome
                .matched
                .iter()
                .map(|m| m.rule_id)
                .collect::<Vec<_>>(),
            vec![1]
        );

        first.stop_processing = false;
        first.exceptions = vec![Condition::SenderGroup { groups: vec![7] }];
        let (rules, _) = Compiled::new(&[disclaimer(2), first]);
        let outcome = rules.evaluate(&envelope(true), &cards(0));
        assert_eq!(
            outcome
                .matched
                .iter()
                .map(|m| m.rule_id)
                .collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[test]
    fn content_conditions() {
        let content = Content {
            subject: "Project Falcon",
            bodies: vec!["see attached".into()],
            headers: vec![("X-Class", "Internal only")],
            attachments: vec![
                Attachment {
                    name: Some("plan.docx"),
                    content_type:
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                            .into(),
                    size: 40_000,
                    extracted: Extracted::Text("IBAN GB29 NWBK 6016 1331 9268 19".into()),
                },
                Attachment {
                    name: Some("scan.pdf"),
                    content_type: "application/pdf".into(),
                    size: 900_000,
                    extracted: Extracted::NotInspectable(Why::Pdf),
                },
            ],
            size: 1_000_000,
            truncated: false,
        };
        let block = || Action::Block { notice: "n".into() };
        let checks = [
            (
                Condition::Words {
                    words: vec!["project falcon".into()],
                    at_least: 1,
                },
                true,
            ),
            (
                Condition::Header {
                    name: "x-class".into(),
                    contains: Some("internal".into()),
                    matches: None,
                },
                true,
            ),
            (
                Condition::AttachmentExtension {
                    extensions: vec![".PDF".into()],
                },
                true,
            ),
            (
                Condition::AttachmentType {
                    types: vec!["image/".into()],
                },
                false,
            ),
            (Condition::AttachmentSizeOver { bytes: 500_000 }, true),
            (Condition::AttachmentCountOver { count: 2 }, false),
            (Condition::CantBeInspected, true),
            (Condition::MessageSizeOver { bytes: 2_000_000 }, false),
            (
                Condition::Detected {
                    detectors: vec![DetectorMin {
                        id: "iban".into(),
                        at_least: 1,
                    }],
                },
                true,
            ),
            (
                Condition::SenderDomain {
                    domains: vec!["EXAMPLE.com".into()],
                },
                true,
            ),
        ];
        for (condition, expected) in checks {
            let (rules, skipped) =
                Compiled::new(&[rule(1, Kind::Dlp, vec![condition.clone()], block())]);
            assert!(skipped.is_empty(), "{condition:?}");
            let matched = !rules.evaluate(&envelope(true), &content).matched.is_empty();
            assert_eq!(matched, expected, "{condition:?}");
        }
    }

    #[test]
    fn direction_and_disabled_rules() {
        let mut r = five_cards_outside(Action::Block { notice: "n".into() });
        let (rules, _) = Compiled::new(std::slice::from_ref(&r));
        assert!(rules.applies_to(true) && !rules.applies_to(false));
        let mut incoming = envelope(true);
        incoming.outgoing = false;
        assert_eq!(
            rules.evaluate(&incoming, &cards(5)).decision(false),
            Decision::Pass
        );
        r.enabled = false;
        assert!(Compiled::new(&[r]).0.is_empty());
    }
}
