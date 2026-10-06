/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Mail flow rules and DLP rules (dlp-and-mail-flow-rules spec, §2.2–§2.4):
//! what a rule is, what makes one valid, and where it's kept.
//!
//! Kept in the fork's subspace (`store::SUBSPACE_INBUXA`), never in the
//! registry, so an upstream schema import never touches them. Every key
//! starts with `R`, then one byte for the kind:
//!
//! - `r` + rule id (u32): the rule, as JSON.
//!
//! Numbers are big-endian. There are few rules, so they're read whole.

use super::{detectors, words};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize, de::DeserializeOwned};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue},
};
use trc::AddContext;

const FEATURE: u8 = b'R';
const KIND_RULE: u8 = b'r';
const CREATE_ATTEMPTS: usize = 5;

/// Longest text a rule may carry (a notice, a disclaimer), in bytes.
const MAX_TEXT: usize = 16 * 1024;
/// Most entries in one list (words, addresses, domains).
const MAX_LIST: usize = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    Dlp,
    Transport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    /// Mail an authenticated sender submits, over SMTP or JMAP.
    Outgoing,
    /// Everything else the server accepts.
    Incoming,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub enum Position {
    Top,
    Bottom,
}

fn one() -> u32 {
    1
}

/// Group and tenant ids in the JMAP form clients use (`"b"`, `"c"`…), held
/// as numbers for matching. Plain numbers are read too.
pub(crate) mod jmap_ids {
    use serde::{Deserialize, Deserializer, Serializer, de::Error, ser::SerializeSeq};
    use std::str::FromStr;
    use types::id::Id;

    pub fn serialize<S: Serializer>(ids: &[u32], serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(ids.len()))?;
        for id in ids {
            seq.serialize_element(&Id::from(*id).to_string())?;
        }
        seq.end()
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Either {
        Text(String),
        Number(u32),
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u32>, D::Error> {
        Vec::<Either>::deserialize(deserializer)?
            .into_iter()
            .map(|id| match id {
                Either::Number(n) => Ok(n),
                Either::Text(text) => Id::from_str(&text)
                    .map(|id| id.document_id())
                    .map_err(|_| D::Error::custom(format!("\"{text}\" isn't an id"))),
            })
            .collect()
    }
}

/// One id in the same form.
pub(crate) mod jmap_id {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    use std::str::FromStr;
    use types::id::Id;

    pub fn serialize<S: Serializer>(id: &u32, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&Id::from(*id).to_string())
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Either {
        Text(String),
        Number(u32),
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
        match Either::deserialize(deserializer)? {
            Either::Number(n) => Ok(n),
            Either::Text(text) => Id::from_str(&text)
                .map(|id| id.document_id())
                .map_err(|_| D::Error::custom(format!("\"{text}\" isn't an id"))),
        }
    }
}

/// A detector and the least it must find.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectorMin {
    pub id: String,
    #[serde(default = "one")]
    pub at_least: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Condition {
    SenderAddress {
        addresses: Vec<String>,
    },
    SenderDomain {
        domains: Vec<String>,
    },
    SenderGroup {
        #[serde(with = "jmap_ids")]
        groups: Vec<u32>,
    },
    SenderTenant {
        #[serde(with = "jmap_ids")]
        tenants: Vec<u32>,
    },
    /// Any recipient is one of these.
    RecipientAddress {
        addresses: Vec<String>,
    },
    RecipientDomain {
        domains: Vec<String>,
    },
    RecipientGroup {
        #[serde(with = "jmap_ids")]
        groups: Vec<u32>,
    },
    /// Any recipient isn't at a domain this server hosts.
    RecipientOutside,
    /// Words or phrases in the subject, body or readable attachments.
    Words {
        words: Vec<String>,
        #[serde(default = "one")]
        at_least: u32,
    },
    /// The organization's regular expression, in the same places.
    Pattern {
        pattern: String,
        #[serde(default = "one")]
        at_least: u32,
    },
    /// A header exists, or its value contains or matches.
    Header {
        name: String,
        #[serde(default)]
        contains: Option<String>,
        #[serde(default)]
        matches: Option<String>,
    },
    /// An attachment's declared or detected type starts with one of these.
    AttachmentType {
        types: Vec<String>,
    },
    AttachmentExtension {
        extensions: Vec<String>,
    },
    AttachmentName {
        pattern: String,
    },
    AttachmentSizeOver {
        bytes: u64,
    },
    AttachmentCountOver {
        count: u32,
    },
    /// An attachment is encrypted, a PDF, a legacy Office file, an archive
    /// inside an archive, or past the inspection limit.
    CantBeInspected,
    MessageSizeOver {
        bytes: u64,
    },
    /// Any of these detectors finds at least its minimum (DLP rules only).
    Detected {
        detectors: Vec<DetectorMin>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Action {
    // Transport actions
    AddDisclaimer {
        text: String,
        #[serde(default)]
        html: Option<String>,
        position: Position,
    },
    AddHeader {
        name: String,
        value: String,
    },
    RemoveHeader {
        name: String,
    },
    PrefixSubject {
        text: String,
    },
    AddRecipient {
        address: String,
    },
    Redirect {
        addresses: Vec<String>,
    },
    Refuse {
        text: String,
    },
    Route {
        queue: String,
    },
    /// Journaling spec, JR-10: a copy into this journal, whatever its scope.
    Journal {
        #[serde(with = "jmap_id")]
        journal: u32,
    },
    // DLP actions
    Block {
        notice: String,
    },
    Warn {
        notice: String,
    },
    Hold {
        notice: String,
        #[serde(default)]
        notify_sender: bool,
    },
}

impl Action {
    pub fn is_dlp(&self) -> bool {
        matches!(
            self,
            Action::Block { .. } | Action::Warn { .. } | Action::Hold { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    #[serde(default)]
    pub id: u32,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub kind: Kind,
    #[serde(default = "enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
    pub direction: Direction,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    #[serde(default)]
    pub exceptions: Vec<Condition>,
    pub actions: Vec<Action>,
    #[serde(default)]
    pub stop_processing: bool,
    #[serde(default)]
    pub created_by: String,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
}

fn enabled() -> bool {
    true
}

/// Why a rule can't be saved: the property at fault, and a sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid {
    pub property: &'static str,
    pub reason: String,
}

fn invalid(property: &'static str, reason: impl Into<String>) -> Invalid {
    Invalid {
        property,
        reason: reason.into(),
    }
}

impl Rule {
    /// Everything that can be checked without the rest of the server: the
    /// shape (§2.2, §2.4), the detectors, word lists and patterns.
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.name.trim().is_empty() {
            return Err(invalid("name", "A rule needs a name."));
        }
        if self.name.len() > 200 || self.description.len() > MAX_TEXT {
            return Err(invalid("name", "The name or description is too long."));
        }
        if self.actions.is_empty() {
            return Err(invalid("actions", "A rule needs something to do."));
        }
        let dlp_actions = self.actions.iter().filter(|a| a.is_dlp()).count();
        match self.kind {
            Kind::Dlp => {
                if self.direction != Direction::Outgoing {
                    return Err(invalid("direction", "DLP rules check outgoing mail only."));
                }
                // One of block, warn or hold; journaling may go with it
                if dlp_actions != 1
                    || self
                        .actions
                        .iter()
                        .any(|a| !a.is_dlp() && !matches!(a, Action::Journal { .. }))
                {
                    return Err(invalid(
                        "actions",
                        "A DLP rule has exactly one action: block, warn or hold, and may also journal the message.",
                    ));
                }
            }
            Kind::Transport => {
                if dlp_actions > 0 {
                    return Err(invalid(
                        "actions",
                        "Block, warn and hold belong to DLP rules.",
                    ));
                }
                if self
                    .conditions
                    .iter()
                    .chain(&self.exceptions)
                    .any(|c| matches!(c, Condition::Detected { .. }))
                {
                    return Err(invalid("conditions", "Detectors belong to DLP rules."));
                }
            }
        }
        for (property, list) in [
            ("conditions", &self.conditions),
            ("exceptions", &self.exceptions),
        ] {
            for condition in list {
                validate_condition(condition).map_err(|reason| invalid(property, reason))?;
            }
        }
        for action in &self.actions {
            validate_action(action).map_err(|reason| invalid("actions", reason))?;
        }
        Ok(())
    }
}

fn nonempty_list<T>(list: &[T], what: &str) -> Result<(), String> {
    if list.is_empty() {
        Err(format!("The {what} list is empty."))
    } else if list.len() > MAX_LIST {
        Err(format!(
            "The {what} list is longer than {MAX_LIST} entries."
        ))
    } else {
        Ok(())
    }
}

fn header_name(name: &str) -> Result<(), String> {
    if !name.is_empty()
        && name.len() <= 100
        && name.bytes().all(|b| b.is_ascii_graphic() && b != b':')
    {
        Ok(())
    } else {
        Err(format!("\"{name}\" isn't a header name."))
    }
}

fn text(value: &str, what: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("The {what} is empty."))
    } else if value.len() > MAX_TEXT {
        Err(format!("The {what} is longer than {MAX_TEXT} bytes."))
    } else {
        Ok(())
    }
}

fn validate_condition(condition: &Condition) -> Result<(), String> {
    match condition {
        Condition::SenderAddress { addresses } | Condition::RecipientAddress { addresses } => {
            nonempty_list(addresses, "address")
        }
        Condition::SenderDomain { domains } | Condition::RecipientDomain { domains } => {
            nonempty_list(domains, "domain")
        }
        Condition::SenderGroup { groups } | Condition::RecipientGroup { groups } => {
            nonempty_list(groups, "group")
        }
        Condition::SenderTenant { tenants } => nonempty_list(tenants, "tenant"),
        Condition::Words { words, at_least } => {
            nonempty_list(words, "word")?;
            if *at_least == 0 {
                return Err("The least number of words must be 1 or more.".into());
            }
            words::WordList::new(words).map(|_| ())
        }
        Condition::Pattern { pattern, at_least } => {
            if *at_least == 0 {
                return Err("The least number of matches must be 1 or more.".into());
            }
            words::Pattern::new(pattern).map(|_| ())
        }
        Condition::Header {
            name,
            contains,
            matches,
        } => {
            header_name(name)?;
            if let Some(pattern) = matches {
                words::Pattern::new(pattern)?;
            }
            if contains.is_some() && matches.is_some() {
                return Err("A header condition is either contains or matches.".into());
            }
            Ok(())
        }
        Condition::AttachmentType { types } => nonempty_list(types, "type"),
        Condition::AttachmentExtension { extensions } => nonempty_list(extensions, "extension"),
        Condition::AttachmentName { pattern } => words::Pattern::new(pattern).map(|_| ()),
        Condition::Detected { detectors } => {
            nonempty_list(detectors, "detector")?;
            for d in detectors {
                if detectors::by_id(&d.id).is_none() {
                    return Err(format!("There is no detector \"{}\".", d.id));
                }
                if d.at_least == 0 {
                    return Err("A detector's least count must be 1 or more.".into());
                }
            }
            Ok(())
        }
        Condition::RecipientOutside
        | Condition::AttachmentSizeOver { .. }
        | Condition::AttachmentCountOver { .. }
        | Condition::CantBeInspected
        | Condition::MessageSizeOver { .. } => Ok(()),
    }
}

fn validate_action(action: &Action) -> Result<(), String> {
    match action {
        Action::AddDisclaimer { text: t, html, .. } => {
            text(t, "disclaimer")?;
            html.as_deref()
                .map_or(Ok(()), |h| text(h, "disclaimer's HTML"))
        }
        Action::AddHeader { name, value } => {
            header_name(name)?;
            if value.len() > 998 || value.contains(['\r', '\n']) {
                Err("A header value is one line of at most 998 characters.".into())
            } else {
                Ok(())
            }
        }
        Action::RemoveHeader { name } => header_name(name),
        Action::PrefixSubject { text: t } => text(t, "subject prefix"),
        Action::AddRecipient { address } => {
            if address.contains('@') {
                Ok(())
            } else {
                Err(format!("\"{address}\" isn't an address."))
            }
        }
        Action::Redirect { addresses } => {
            nonempty_list(addresses, "address")?;
            match addresses.iter().find(|a| !a.contains('@')) {
                Some(a) => Err(format!("\"{a}\" isn't an address.")),
                None => Ok(()),
            }
        }
        Action::Refuse { text: t } => text(t, "refusal text"),
        Action::Route { queue } => text(queue, "queue"),
        Action::Journal { .. } => Ok(()),
        Action::Block { notice } | Action::Warn { notice } | Action::Hold { notice, .. } => {
            text(notice, "notice")
        }
    }
}

// --- Storage --------------------------------------------------------------

struct Json<T>(T);

impl<T: SerdeSerialize> Serialize for Json<T> {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        serde_json::to_vec(&self.0).map_err(|err| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to serialize mail rule")
                .reason(err)
        })
    }
}

impl<T: DeserializeOwned + Sync + Send> Deserialize for Json<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid mail rule")
                .reason(err)
        })
    }
}

fn class(id: u32) -> ValueClass {
    let mut key = Vec::with_capacity(6);
    key.push(FEATURE);
    key.push(KIND_RULE);
    key.extend_from_slice(&id.to_be_bytes());
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

fn key(id: u32) -> ValueKey<ValueClass> {
    ValueKey::from(class(id))
}

pub async fn get(data: &Store, id: u32) -> trc::Result<Option<Rule>> {
    Ok(data
        .get_value::<Json<Rule>>(key(id))
        .await
        .caused_by(trc::location!())?
        .map(|Json(rule)| rule))
}

/// Every rule, in the order they run: by priority, then oldest first.
pub async fn all(data: &Store) -> trc::Result<Vec<Rule>> {
    let mut rules = Vec::new();
    data.iterate(IterateParams::new(key(0), key(u32::MAX)), |_, value| {
        if let Ok(Json(rule)) = Json::<Rule>::deserialize(value) {
            rules.push(rule);
        }
        Ok(true)
    })
    .await
    .caused_by(trc::location!())?;
    rules.sort_by_key(|rule| (rule.priority, rule.id));
    Ok(rules)
}

/// Writes a new rule under the next free id, which it returns. Two nodes
/// creating rules at once can't take the same id: the key must be absent.
pub async fn create(data: &Store, rule: &Rule) -> trc::Result<u32> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let id = all(data).await?.iter().map(|r| r.id).max().unwrap_or(0) + 1;
        let stored = Rule { id, ..rule.clone() };
        let mut batch = BatchBuilder::new();
        batch.assert_value(class(id), AssertValue::None);
        batch.set(class(id), Json(&stored).serialize()?);
        match data.write(batch.build_all()).await {
            Ok(_) => {
                super::cache::invalidate();
                return Ok(id);
            }
            Err(err)
                if attempt < CREATE_ATTEMPTS
                    && matches!(
                        err.as_ref(),
                        trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
                    ) => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }
}

/// Replaces a stored rule (same id).
pub async fn update(data: &Store, rule: &Rule) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(class(rule.id), Json(rule).serialize()?);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    super::cache::invalidate();
    Ok(())
}

pub async fn delete(data: &Store, id: u32) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.clear(class(id));
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    super::cache::invalidate();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(kind: Kind, actions: Vec<Action>) -> Rule {
        Rule {
            id: 0,
            name: "Cards outside".into(),
            description: String::new(),
            kind,
            enabled: true,
            priority: 0,
            direction: Direction::Outgoing,
            conditions: vec![Condition::RecipientOutside],
            exceptions: vec![],
            actions,
            stop_processing: false,
            created_by: String::new(),
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn journal_action_goes_with_either_kind() {
        let hold = Action::Hold {
            notice: "Held.".into(),
            notify_sender: false,
        };
        let journal = Action::Journal { journal: 3 };
        assert!(
            rule(Kind::Dlp, vec![hold.clone(), journal.clone()])
                .validate()
                .is_ok()
        );
        assert!(rule(Kind::Dlp, vec![journal.clone()]).validate().is_err());
        assert!(
            rule(
                Kind::Dlp,
                vec![hold, Action::PrefixSubject { text: "x".into() }]
            )
            .validate()
            .is_err()
        );
        assert!(
            rule(Kind::Transport, vec![journal.clone()])
                .validate()
                .is_ok()
        );
        let json = serde_json::to_value(&journal).unwrap();
        assert_eq!(json, serde_json::json!({"type": "journal", "journal": "d"}));
        let back: Action = serde_json::from_value(json).unwrap();
        assert_eq!(back, journal);
    }

    #[test]
    fn wire_format() {
        let json = r#"{"name":"Cards","kind":"dlp","direction":"outgoing",
            "conditions":[{"type":"recipientOutside"},{"type":"detected","detectors":[{"id":"payment-card","atLeast":5}]}],
            "actions":[{"type":"hold","notice":"Held for review","notifySender":true}]}"#;
        let parsed: Rule = serde_json::from_str(json).unwrap();
        assert!(parsed.enabled);
        assert_eq!(
            parsed.conditions[1],
            Condition::Detected {
                detectors: vec![DetectorMin {
                    id: "payment-card".into(),
                    at_least: 5
                }]
            }
        );
        assert_eq!(
            parsed.actions[0],
            Action::Hold {
                notice: "Held for review".into(),
                notify_sender: true
            }
        );
        assert!(parsed.validate().is_ok());
        let back = serde_json::to_value(&parsed).unwrap();
        assert_eq!(back["actions"][0]["notifySender"], true);
    }

    #[test]
    fn group_and_tenant_ids_are_jmap_ids() {
        let condition: Condition =
            serde_json::from_str(r#"{"type":"senderGroup","groups":["b", 7]}"#).unwrap();
        assert_eq!(condition, Condition::SenderGroup { groups: vec![1, 7] });
        assert_eq!(
            serde_json::to_value(&condition).unwrap()["groups"],
            serde_json::json!(["b", "h"])
        );
        assert!(
            serde_json::from_str::<Condition>(r#"{"type":"senderTenant","tenants":["!!"]}"#)
                .is_err()
        );
    }

    #[test]
    fn dlp_rules_have_one_dlp_action_on_outgoing_mail() {
        let block = Action::Block {
            notice: "No.".into(),
        };
        assert!(rule(Kind::Dlp, vec![block.clone()]).validate().is_ok());
        let two = rule(
            Kind::Dlp,
            vec![
                block.clone(),
                Action::Warn {
                    notice: "Hm.".into(),
                },
            ],
        );
        assert_eq!(two.validate().unwrap_err().property, "actions");
        let mixed = rule(
            Kind::Dlp,
            vec![block.clone(), Action::PrefixSubject { text: "[x]".into() }],
        );
        assert_eq!(mixed.validate().unwrap_err().property, "actions");
        let mut inbound = rule(Kind::Dlp, vec![block.clone()]);
        inbound.direction = Direction::Incoming;
        assert_eq!(inbound.validate().unwrap_err().property, "direction");
        assert_eq!(
            rule(Kind::Transport, vec![block])
                .validate()
                .unwrap_err()
                .property,
            "actions"
        );
    }

    #[test]
    fn conditions_and_actions_are_checked() {
        let disclaimer = Action::AddDisclaimer {
            text: "Sent from Example Co.".into(),
            html: None,
            position: Position::Bottom,
        };
        let mut r = rule(Kind::Transport, vec![disclaimer]);
        assert!(r.validate().is_ok());
        r.conditions.push(Condition::Detected {
            detectors: vec![DetectorMin {
                id: "iban".into(),
                at_least: 1,
            }],
        });
        assert_eq!(r.validate().unwrap_err().property, "conditions");

        let mut r = rule(
            Kind::Dlp,
            vec![Action::Block {
                notice: "No.".into(),
            }],
        );
        r.conditions = vec![Condition::Detected {
            detectors: vec![DetectorMin {
                id: "nope".into(),
                at_least: 1,
            }],
        }];
        assert!(r.validate().unwrap_err().reason.contains("nope"));
        r.conditions = vec![Condition::Pattern {
            pattern: "(".into(),
            at_least: 1,
        }];
        assert!(r.validate().is_err());
        r.conditions = vec![Condition::Words {
            words: vec![],
            at_least: 1,
        }];
        assert!(r.validate().is_err());
        r.exceptions = vec![Condition::Header {
            name: "X-Bad: yes".into(),
            contains: None,
            matches: None,
        }];
        r.conditions = vec![];
        assert_eq!(r.validate().unwrap_err().property, "exceptions");

        let header = rule(
            Kind::Transport,
            vec![Action::AddHeader {
                name: "X-Tag".into(),
                value: "a\r\nBcc: x@y".into(),
            }],
        );
        assert!(header.validate().is_err());
        let redirect = rule(
            Kind::Transport,
            vec![Action::Redirect {
                addresses: vec!["nobody".into()],
            }],
        );
        assert!(redirect.validate().is_err());
        let mut unnamed = rule(
            Kind::Transport,
            vec![Action::RemoveHeader {
                name: "X-Tag".into(),
            }],
        );
        unnamed.name = " ".into();
        assert_eq!(unnamed.validate().unwrap_err().property, "name");
    }
}
