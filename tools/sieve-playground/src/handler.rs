/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

// inbuxa: the server's sieve-rs (0.7) hands the host one Event at a time and
// takes an Input back, where the playground this came from implemented a
// Handler trait; the answers and the events recorded are the same.

use std::collections::BTreeSet;

use mail_parser::MessageParser;
use sieve::{
    Envelope, Event as SieveEvent, Importance, Input, Mailbox, MatchAs, Recipient,
    compiler::grammar::actions::action_redirect::{ByMode, ByTime, Notify, NotifyItem, Ret},
};

use crate::{
    output::{Detail, Event, OutputMessage},
    settings::Settings,
};

/// What a message the script created is, read from its Auto-Submitted
/// header: 0.7 does not say whether a SendMessage is a redirect.
#[derive(Clone, Copy)]
enum Created {
    Vacation,
    Notification,
    Other,
}

pub struct Recorder<'s> {
    settings: &'s Settings,
    seen_ids: &'s [String],
    created: Vec<(usize, Created)>,
    pub new_ids: BTreeSet<String>,
    pub events: Vec<Event>,
    pub messages: Vec<OutputMessage>,
    pub after_error: bool,
}

impl<'s> Recorder<'s> {
    pub fn new(settings: &'s Settings, seen_ids: &'s [String]) -> Self {
        Recorder {
            settings,
            seen_ids,
            created: Vec::new(),
            new_ids: BTreeSet::new(),
            events: Vec::new(),
            messages: Vec::new(),
            after_error: false,
        }
    }

    fn has_mailbox(&self, name: &str, special_use: &[String]) -> bool {
        self.settings.mailboxes.iter().any(|mailbox| {
            (mailbox.name == name
                || (name.eq_ignore_ascii_case("INBOX")
                    && mailbox.name.eq_ignore_ascii_case("INBOX")))
                && special_use.iter().all(|wanted| {
                    mailbox
                        .special_use
                        .iter()
                        .any(|have| have.eq_ignore_ascii_case(wanted))
                })
        })
    }

    fn push(
        &mut self,
        kind: &'static str,
        summary: String,
        detail: Vec<Detail>,
        message_id: usize,
    ) {
        self.events.push(Event {
            kind,
            summary,
            detail,
            message_id,
            is_final: matches!(kind, "keep" | "discard" | "reject"),
            after_error: self.after_error,
        });
    }

    /// Answers every event but IncludeScript, which needs the compiled
    /// include tabs and is answered by the caller.
    pub fn answer(&mut self, event: SieveEvent) -> Input {
        match event {
            SieveEvent::IncludeScript { .. } => Input::False,
            SieveEvent::MailboxExists {
                mailboxes,
                special_use,
            } => {
                let exists = if mailboxes.is_empty() {
                    special_use.iter().all(|wanted| {
                        self.settings.mailboxes.iter().any(|mailbox| {
                            mailbox
                                .special_use
                                .iter()
                                .any(|have| have.eq_ignore_ascii_case(wanted))
                        })
                    })
                } else {
                    mailboxes.iter().all(|mailbox| match mailbox {
                        Mailbox::Name(name) => self.has_mailbox(name, &special_use),
                        Mailbox::Id(_) => false,
                    })
                };
                exists.into()
            }
            SieveEvent::ListContains {
                lists,
                values,
                match_as,
            } => self
                .settings
                .lists
                .iter()
                .filter(|list| lists.contains(&list.name))
                .flat_map(|list| list.values.iter())
                .any(|entry| {
                    values.iter().any(|value| match match_as {
                        MatchAs::Octet => entry == value,
                        MatchAs::Lowercase => entry.eq_ignore_ascii_case(value),
                        MatchAs::Number => {
                            match (entry.trim().parse::<f64>(), value.trim().parse::<f64>()) {
                                (Ok(a), Ok(b)) => a == b,
                                _ => false,
                            }
                        }
                    })
                })
                .into(),
            SieveEvent::DuplicateId { id, .. } => {
                let seen = self.seen_ids.iter().any(|seen| *seen == id);
                if !seen {
                    self.new_ids.insert(id);
                }
                seen.into()
            }
            SieveEvent::Function { .. } => {
                // The only external function a user script can call is
                // llm_prompt, which needs the server's model. The server
                // answers false when it has none.
                self.push(
                    "function",
                    "llm_prompt is not run here".into(),
                    vec![Detail::new("result", "false, as on a server without a model")],
                    0,
                );
                Input::FncResult(false.into())
            }
            SieveEvent::Keep { flags, message_id } => {
                self.push(
                    "keep",
                    "Keep the message in INBOX".into(),
                    flags_detail(&flags),
                    message_id,
                );
                Input::True
            }
            SieveEvent::Discard => {
                self.push(
                    "discard",
                    "Discard the message silently".into(),
                    Vec::new(),
                    0,
                );
                Input::True
            }
            SieveEvent::Reject { extended, reason } => {
                let mut detail = vec![Detail::new("reason", reason)];
                if extended {
                    detail.push(Detail::new("type", "ereject (SMTP level)"));
                }
                self.push("reject", "Reject the message".into(), detail, 0);
                Input::True
            }
            SieveEvent::FileInto {
                folder,
                flags,
                mailbox_id,
                special_use,
                create,
                message_id,
            } => {
                let mut detail = flags_detail(&flags);
                detail.extend(mailbox_id.map(|id| Detail::new("mailbox id", id)));
                detail
                    .extend(special_use.map(|special_use| Detail::new("special use", special_use)));
                if create {
                    detail.push(Detail::new("create", "if missing"));
                }
                if !self.has_mailbox(&folder, &[]) && !create {
                    detail.push(Detail::new("warning", "mailbox not in settings"));
                }
                self.push(
                    "fileinto",
                    format!("File into {folder}"),
                    detail,
                    message_id,
                );
                Input::True
            }
            SieveEvent::SendMessage {
                recipient,
                notify,
                return_of_content,
                by_time,
                message_id,
            } => {
                self.send_message(recipient, notify, return_of_content, by_time, message_id);
                Input::True
            }
            SieveEvent::Notify {
                from,
                importance,
                options,
                message,
                method,
            } => {
                let mut detail = Vec::new();
                detail.extend(from.map(|from| Detail::new("from", from)));
                match importance {
                    Importance::High => detail.push(Detail::new("importance", "high")),
                    Importance::Low => detail.push(Detail::new("importance", "low")),
                    Importance::Normal => (),
                }
                if !message.is_empty() {
                    detail.push(Detail::new("message", message));
                }
                if !options.is_empty() {
                    detail.push(Detail::new("options", options.join(", ")));
                }
                self.push("notify", format!("Notify {method}"), detail, 0);
                Input::True
            }
            SieveEvent::SetEnvelope { envelope, value } => {
                let field = match envelope {
                    Envelope::From => "from",
                    Envelope::To => "to",
                    Envelope::ByTimeAbsolute => "bytimeabsolute",
                    Envelope::ByTimeRelative => "bytimerelative",
                    Envelope::ByMode => "bymode",
                    Envelope::ByTrace => "bytrace",
                    Envelope::Notify => "notify",
                    Envelope::Orcpt => "orcpt",
                    Envelope::Ret => "ret",
                    Envelope::Envid => "envid",
                };
                self.push(
                    "envelope",
                    format!("Set envelope {field} to {value}"),
                    Vec::new(),
                    0,
                );
                Input::True
            }
            SieveEvent::CreatedMessage {
                message_id,
                message,
            } => {
                self.created.push((message_id, created_kind(&message)));
                self.push(
                    "created",
                    format!("Generated message #{message_id}"),
                    vec![Detail::new("size", format!("{} bytes", message.len()))],
                    message_id,
                );
                self.messages
                    .push(OutputMessage::parse(message_id, &message));
                Input::True
            }
        }
    }

    fn send_message(
        &mut self,
        recipient: Recipient,
        notify: Notify,
        return_of_content: Ret,
        by_time: ByTime<i64>,
        message_id: usize,
    ) {
        let to = match &recipient {
            Recipient::Address(address) => address.clone(),
            Recipient::List(list) => format!("list {list}"),
            Recipient::Group(group) => group.join(", "),
        };
        let created = self
            .created
            .iter()
            .find(|(id, _)| *id == message_id)
            .map(|(_, kind)| *kind);
        let (kind, summary) = match created {
            Some(Created::Vacation) => ("vacation", format!("Send a vacation reply to {to}")),
            Some(Created::Notification) => {
                ("notification", format!("Send a notification to {to}"))
            }
            Some(Created::Other) | None => ("redirect", format!("Redirect to {to}")),
        };
        let mut detail = Vec::new();
        if let Recipient::Group(group) = &recipient
            && group.len() > 1
        {
            detail.push(Detail::new("recipients", group.len().to_string()));
        }
        match notify {
            Notify::Never if kind == "redirect" => detail.push(Detail::new("dsn notify", "never")),
            Notify::Never => (),
            Notify::Items(items) => detail.push(Detail::new(
                "dsn notify",
                items
                    .iter()
                    .map(|item| match item {
                        NotifyItem::Success => "success",
                        NotifyItem::Failure => "failure",
                        NotifyItem::Delay => "delay",
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            )),
            Notify::Default => (),
        }
        match return_of_content {
            Ret::Full => detail.push(Detail::new("dsn ret", "full")),
            Ret::Hdrs => detail.push(Detail::new("dsn ret", "headers")),
            Ret::Default => (),
        }
        match by_time {
            ByTime::Relative {
                rlimit,
                mode,
                trace,
            } => {
                detail.push(Detail::new("deliver within", format!("{rlimit}s")));
                push_by_mode(&mut detail, mode, trace);
            }
            ByTime::Absolute {
                alimit,
                mode,
                trace,
            } => {
                detail.push(Detail::new("deliver by", alimit.to_string()));
                push_by_mode(&mut detail, mode, trace);
            }
            ByTime::None => (),
        }
        self.push(kind, summary, detail, message_id);
    }
}

fn created_kind(message: &[u8]) -> Created {
    let auto_submitted = MessageParser::new()
        .parse_headers(message)
        .and_then(|message| {
            message
                .header_raw("Auto-Submitted")
                .map(|value| value.trim().to_ascii_lowercase())
        });
    match auto_submitted.as_deref() {
        Some(value) if value.starts_with("auto-replied") => Created::Vacation,
        Some(value) if value.starts_with("auto-notified") => Created::Notification,
        _ => Created::Other,
    }
}

fn flags_detail(flags: &[String]) -> Vec<Detail> {
    if flags.is_empty() {
        Vec::new()
    } else {
        vec![Detail::new("flags", flags.join(" "))]
    }
}

fn push_by_mode(detail: &mut Vec<Detail>, mode: ByMode, trace: bool) {
    match mode {
        ByMode::Notify => detail.push(Detail::new("by mode", "notify")),
        ByMode::Return => detail.push(Detail::new("by mode", "return")),
        ByMode::Default => (),
    }
    if trace {
        detail.push(Detail::new("by trace", "yes"));
    }
}
