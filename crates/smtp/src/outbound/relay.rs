/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Outbound mail through an inbuxa Relay (relay spec, "Outbound routing",
//! RL-20, RL-24).
//!
//! With a relay's `sendThrough` on, every non-local recipient is handed to
//! one of the relays this node is linked to, in turn. The recipients stay
//! in this server's queue, marked [`RCPT_RELAYED`] and shown as handed to
//! the relay, until the link service reports the relay's final status for
//! them through [`apply_relayed`]. The usual DSNs follow from there. With
//! no relay linked, they wait in the queue and are retried as usual.

use super::DeliveryResult;
use crate::queue::{
    Error, ErrorDetails, HostResponse, MessageWrapper, RCPT_RELAYED, Status, UnexpectedResponse,
    spool::SmtpSpool,
};
use common::{Server, config::smtp::queue::QueueName, ipc::QueueEvent};
use inbuxa_features::relay::outbound::{Handed, Refused, record_handed};
use inbuxa_relay_proto::types::{Address, Envelope};
use smtp_proto::{
    MAIL_BODY_8BITMIME, MAIL_RET_FULL, MAIL_RET_HDRS, RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE,
    RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS, Response,
};
use std::collections::BTreeMap;
use store::write::now;
use trc::RelayEvent;
use types::id::Id;

/// How long a recipient handed to a relay waits before the queue looks at
/// it again. The relay's status normally comes first.
pub const RELAYED_RECHECK: u64 = 3_600;

impl MessageWrapper {
    /// Hands one domain's recipients to the first relay that takes them.
    pub(super) async fn hand_to_relay(
        &self,
        rcpt_idxs: &[usize],
        rcpt_headers: Option<&[u8]>,
        results: &mut Vec<DeliveryResult>,
        server: &Server,
    ) {
        let candidates = server.inner.data.relay_senders.candidates();
        if candidates.is_empty() {
            let status = Status::TemporaryFailure(ErrorDetails {
                entity: "relay".into(),
                details: Error::ConnectionError("No relay is linked from this node.".into()),
            });
            results.push(DeliveryResult::domain(status, rcpt_idxs.to_vec()));
            return;
        }
        let blob = match server
            .get_message_blob(self.message.blob_hash.as_slice(), 0..usize::MAX)
            .await
        {
            Ok(Some(blob)) => blob,
            Ok(None) => {
                let status = Status::PermanentFailure(ErrorDetails {
                    entity: "localhost".into(),
                    details: Error::Io("The message is gone from the blob store.".into()),
                });
                results.push(DeliveryResult::domain(status, rcpt_idxs.to_vec()));
                return;
            }
            Err(err) => {
                trc::error!(
                    err.details("Failed to read a message to hand to a relay")
                        .span_id(self.span_id)
                );
                let status = Status::TemporaryFailure(ErrorDetails {
                    entity: "localhost".into(),
                    details: Error::Io("The message couldn't be read.".into()),
                });
                results.push(DeliveryResult::domain(status, rcpt_idxs.to_vec()));
                return;
            }
        };
        let mut message = Vec::with_capacity(blob.len() + rcpt_headers.map_or(0, |h| h.len()));
        if let Some(headers) = rcpt_headers {
            message.extend_from_slice(headers);
        }
        message.extend_from_slice(&blob);
        drop(blob);
        let envelope = self.relay_envelope(rcpt_idxs);
        let recipients: Vec<String> = envelope.rcpt_to.iter().map(|r| r.email.clone()).collect();

        let mut last = String::new();
        for relay in candidates {
            match relay
                .sender
                .hand_over(message.clone(), envelope.clone())
                .await
            {
                Ok(outbound_id) => {
                    let handed = Handed {
                        id: outbound_id.clone(),
                        queue_id: self.queue_id,
                        queue_name: self.queue_name.as_str().to_string(),
                        recipients: recipients.clone(),
                        at: now(),
                    };
                    if let Err(err) = record_handed(server.store(), relay.relay_id, &handed).await {
                        // The relay sends it anyway; only its status is lost
                        trc::error!(
                            err.details("Failed to record a message handed to a relay")
                                .span_id(self.span_id)
                        );
                    }
                    trc::event!(
                        Relay(RelayEvent::Event),
                        SpanId = self.span_id,
                        Id = Id::from(relay.relay_id).to_string(),
                        Type = "outbound.handed-over",
                        Details = outbound_id,
                        To = recipients
                            .iter()
                            .map(|r| trc::Value::String(r.as_str().into()))
                            .collect::<Vec<_>>(),
                    );
                    for &rcpt_idx in rcpt_idxs {
                        results.push(DeliveryResult::Relayed {
                            relay: relay.name.as_str().into(),
                            rcpt_idx,
                        });
                    }
                    return;
                }
                Err(Refused::Permanent(reply)) => {
                    let status = Status::PermanentFailure(ErrorDetails {
                        entity: relay.name.as_str().into(),
                        details: Error::UnexpectedResponse(UnexpectedResponse {
                            command: "".into(),
                            response: parse_reply(&reply),
                        }),
                    });
                    results.push(DeliveryResult::domain(status, rcpt_idxs.to_vec()));
                    return;
                }
                Err(Refused::Temporary(reason)) => {
                    last = format!("Relay {}: {reason}", relay.name);
                }
            }
        }
        let status = Status::TemporaryFailure(ErrorDetails {
            entity: "relay".into(),
            details: Error::ConnectionError(last.into()),
        });
        results.push(DeliveryResult::domain(status, rcpt_idxs.to_vec()));
    }

    /// The envelope as the relay takes it: the DSN parameters this server
    /// would send itself, and 8BITMIME (RFC 8621 `Address` parameters).
    fn relay_envelope(&self, rcpt_idxs: &[usize]) -> Envelope {
        let flags = self.message.flags;
        let mut from = BTreeMap::new();
        if flags & MAIL_BODY_8BITMIME != 0 {
            from.insert("BODY".to_string(), Some("8BITMIME".to_string()));
        }
        if flags & MAIL_RET_FULL != 0 {
            from.insert("RET".to_string(), Some("FULL".to_string()));
        } else if flags & MAIL_RET_HDRS != 0 {
            from.insert("RET".to_string(), Some("HDRS".to_string()));
        }
        if let Some(env_id) = &self.message.env_id {
            from.insert("ENVID".to_string(), Some(env_id.to_string()));
        }
        let rcpt_to = rcpt_idxs
            .iter()
            .map(|&idx| {
                let rcpt = &self.message.recipients[idx];
                let mut notify = Vec::new();
                for (flag, name) in [
                    (RCPT_NOTIFY_SUCCESS, "SUCCESS"),
                    (RCPT_NOTIFY_DELAY, "DELAY"),
                    (RCPT_NOTIFY_FAILURE, "FAILURE"),
                ] {
                    if rcpt.flags & flag != 0 {
                        notify.push(name);
                    }
                }
                if notify.is_empty() && rcpt.flags & RCPT_NOTIFY_NEVER != 0 {
                    notify.push("NEVER");
                }
                Address {
                    email: rcpt.address().to_string(),
                    parameters: (!notify.is_empty())
                        .then(|| [("NOTIFY".to_string(), Some(notify.join(",")))].into()),
                }
            })
            .collect();
        Envelope {
            mail_from: Address {
                email: self.message.return_path.to_string(),
                parameters: (!from.is_empty()).then_some(from),
            },
            rcpt_to,
        }
    }
}

/// `550 5.1.1 text` as a reply. A reply without an enhanced code gets its
/// class's.
pub fn parse_reply(reply: &str) -> Response<Box<str>> {
    let reply = reply.trim();
    let (code, rest) = reply.split_once(' ').unwrap_or((reply, ""));
    let code = code
        .parse::<u16>()
        .ok()
        .filter(|c| (200..600).contains(c))
        .unwrap_or(451);
    let class = (code / 100) as u8;
    let mut esc = [class, 0, 0];
    let mut message = rest;
    if let Some((first, after)) = rest.split_once(' ').or(Some((rest, "")))
        && let [a, b, c] = first.split('.').collect::<Vec<_>>()[..]
        && let (Ok(a), Ok(b), Ok(c)) = (a.parse::<u8>(), b.parse::<u8>(), c.parse::<u8>())
        && a == class
    {
        esc = [a, b, c];
        message = after;
    }
    Response {
        code,
        esc,
        message: message.into(),
    }
}

/// What a relay says became of one recipient handed to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayedStatus {
    Delivered {
        reply: String,
        mx: Option<String>,
    },
    Refused {
        reply: String,
        mx: Option<String>,
    },
    /// Still queued at the relay, with its last reply, if any.
    Queued {
        reply: String,
        mx: Option<String>,
    },
    /// The relay no longer has the message: hand it over again.
    Lost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    Done,
    /// The queue is working on the message: try again later.
    Locked,
    /// The message is no longer queued here.
    Gone,
}

/// Records a relay's statuses for recipients it was handed, by address,
/// and wakes the queue to send any DSN they call for.
pub async fn apply_relayed(
    server: &Server,
    queue_id: u64,
    queue_name: &str,
    relay: &str,
    statuses: &[(String, RelayedStatus)],
) -> Applied {
    let Some(queue_name) = QueueName::new(queue_name) else {
        return Applied::Gone;
    };
    if !server.try_lock_event(queue_id, queue_name).await {
        return Applied::Locked;
    }
    let Some(mut message) = server.read_message(queue_id, queue_name).await else {
        server.unlock_event(queue_id, queue_name).await;
        return Applied::Gone;
    };
    message.span_id = server.inner.data.span_id_gen.generate();
    let now = now();
    let mut changed = false;
    let mut wake = false;
    for rcpt in message.message.recipients.iter_mut() {
        // Expired here meanwhile: this server's word stands
        if rcpt.flags & RCPT_RELAYED == 0
            || matches!(
                rcpt.status,
                Status::Completed(_) | Status::PermanentFailure(_)
            )
        {
            continue;
        }
        let Some((_, status)) = statuses
            .iter()
            .find(|(address, _)| address.eq_ignore_ascii_case(rcpt.address()))
        else {
            continue;
        };
        let entity = |mx: &Option<String>| -> Box<str> { mx.as_deref().unwrap_or(relay).into() };
        let new = match status {
            RelayedStatus::Delivered { reply, mx } => Status::Completed(HostResponse {
                hostname: entity(mx),
                response: parse_reply(reply),
            }),
            RelayedStatus::Refused { reply, mx } => Status::PermanentFailure(ErrorDetails {
                entity: entity(mx),
                details: Error::UnexpectedResponse(UnexpectedResponse {
                    command: "".into(),
                    response: parse_reply(reply),
                }),
            }),
            RelayedStatus::Queued { reply, mx } if !reply.is_empty() => {
                Status::TemporaryFailure(ErrorDetails {
                    entity: entity(mx),
                    details: Error::UnexpectedResponse(UnexpectedResponse {
                        command: "".into(),
                        response: parse_reply(reply),
                    }),
                })
            }
            RelayedStatus::Queued { .. } => continue,
            RelayedStatus::Lost => Status::TemporaryFailure(ErrorDetails {
                entity: relay.into(),
                details: Error::Io("The relay no longer has the message.".into()),
            }),
        };
        if matches!(
            status,
            RelayedStatus::Delivered { .. } | RelayedStatus::Refused { .. } | RelayedStatus::Lost
        ) {
            rcpt.flags &= !RCPT_RELAYED;
            rcpt.retry.due = now;
            wake = true;
        }
        if rcpt.status != new {
            rcpt.status = new;
            changed = true;
        }
    }
    if changed || wake {
        message
            .save_changes(server, None, wake.then_some(now))
            .await;
    }
    server.unlock_event(queue_id, queue_name).await;
    if wake {
        let _ = server.inner.ipc.queue_tx.send(QueueEvent::Refresh).await;
    }
    Applied::Done
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies() {
        let r = parse_reply("550 5.1.1 No such user here");
        assert_eq!(
            (r.code, r.esc, r.message.as_ref()),
            (550, [5, 1, 1], "No such user here")
        );
        let r = parse_reply("250 Ok");
        assert_eq!((r.code, r.esc, r.message.as_ref()), (250, [2, 0, 0], "Ok"));
        // An enhanced code of another class isn't one
        let r = parse_reply("451 5.1.1 odd");
        assert_eq!(
            (r.code, r.esc, r.message.as_ref()),
            (451, [4, 0, 0], "5.1.1 odd")
        );
        let r = parse_reply("");
        assert_eq!((r.code, r.esc), (451, [4, 0, 0]));
        let r = parse_reply("552 5.3.4");
        assert_eq!((r.code, r.esc, r.message.as_ref()), (552, [5, 3, 4], ""));
    }
}
