/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: RL-23: a message an inbuxa Relay took on port 25, judged here as
//! if this server had taken the SMTP session itself.
//!
//! The relay's session is played again against this server's own handlers:
//! connect, EHLO, MAIL FROM, every RCPT TO, then DATA, with the original
//! sender's address, port and HELO. SPF, reverse IP, DMARC, DNSBL, the spam
//! filter, the AI classifier, Sieve and the directory all see the real
//! facts, and the answer is the one this server would have given.
//!
//! Only the relay link service calls this, for a relay whose key it pinned.
//! Mail arriving on this server's own port 25 is never treated as relayed.

use crate::{
    core::{Relayed, Session, SessionData, SessionParameters, State},
    queue::{
        Error, ErrorDetails, MessageSource, Recipient, Status, UnexpectedResponse, dsn::SendDsn,
        spool::SmtpSpool,
    },
};
use common::{
    Server,
    network::{ServerInstance, stream::NullIo},
};
use mail_auth::SpfResult;
use smtp_proto::{
    MAIL_RET_FULL, MAIL_RET_HDRS, MailFrom, RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE,
    RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS, RcptTo, Request, Response,
    request::receiver::RequestReceiver,
};
use std::{borrow::Cow, net::IpAddr, sync::Arc, time::Duration};
use store::write::{BatchBuilder, BlobLink, BlobOp, now};
use types::blob_hash::BlobHash;

/// An address and its SMTP parameters, as the relay passed them on.
pub type EnvelopeAddress = (String, Vec<(String, Option<String>)>);

/// The session a relay took a message in, and the message.
pub struct RelayedMessage {
    pub relayed: Relayed,
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub helo: String,
    /// The return path and its MAIL FROM parameters.
    pub mail_from: EnvelopeAddress,
    /// Each recipient and its RCPT TO parameters.
    pub rcpt_to: Vec<EnvelopeAddress>,
    pub message: Vec<u8>,
}

/// What this server answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayedOutcome {
    /// Queued for every recipient but those in `refused`, each with its
    /// reply.
    Accepted { refused: Vec<(String, String)> },
    /// Refused as a whole, with this reply. `refused` has the recipients
    /// refused one by one before it, if any.
    Refused {
        reply: String,
        refused: Vec<(String, String)>,
    },
}

/// How long a held message's headers stay stored for its DSN.
const DSN_HEADERS_FOR: u64 = 600;

/// Runs `input` through this server's inbound pipeline. A held message's
/// refusals are reported to its sender only when the sender passed SPF or
/// DMARC here (RL-18); a live one's whole refusal is the relay's to give.
pub async fn ingest_relayed(
    server: Server,
    instance: Arc<ServerInstance>,
    input: RelayedMessage,
) -> RelayedOutcome {
    let session_id = instance.span_id_gen.generate();
    let asn_geo_data = server.lookup_asn_country(input.remote_ip).await;
    // Port 25: the relay took it on port 25, and this server's settings
    // tell port 25 from submission by it
    let mut data = SessionData::new(
        input.local_ip,
        25,
        input.remote_ip,
        input.remote_port,
        asn_geo_data,
        session_id,
    );
    let held = input.relayed.held;
    data.relayed = Some(input.relayed);
    let mut session = Session {
        hostname: String::new(),
        state: State::None,
        instance,
        server,
        stream: NullIo::default(),
        data,
        params: SessionParameters::default(),
    };

    let mut lines = Lines::default();
    let outcome = Box::pin(session.play(
        input.helo,
        input.mail_from,
        input.rcpt_to,
        input.message,
        &mut lines,
    ))
    .await;
    if held {
        let refused = match &outcome {
            RelayedOutcome::Accepted { refused } => refused.clone(),
            RelayedOutcome::Refused { reply, refused } if reply.starts_with('5') => {
                // Every recipient that got as far as RCPT, refused at once
                let mut all = refused.clone();
                all.extend(
                    session
                        .data
                        .rcpt_to
                        .iter()
                        .map(|rcpt| (rcpt.address.clone(), reply.clone())),
                );
                all
            }
            RelayedOutcome::Refused { .. } => Vec::new(),
        };
        if !refused.is_empty() {
            session.bounce_held(&refused, &lines).await;
        }
    }
    outcome
}

/// The MAIL FROM and RCPT TO commands as parsed, for a DSN.
#[derive(Default)]
struct Lines {
    mail_from: Option<MailFrom<String>>,
    rcpt_to: Vec<RcptTo<String>>,
}

impl Session<NullIo> {
    async fn play(
        &mut self,
        helo: String,
        mail_from: EnvelopeAddress,
        rcpt_to: Vec<EnvelopeAddress>,
        message: Vec<u8>,
        lines: &mut Lines,
    ) -> RelayedOutcome {
        let mut refused = Vec::new();
        let refuse = |reply: String, refused: Vec<(String, String)>| RelayedOutcome::Refused {
            reply,
            refused,
        };

        // Connect: rate limits, then the connect stage's scripts and filters
        if !self.is_allowed().await {
            return refuse(
                "421 4.7.0 Too many connections, try again later.".into(),
                refused,
            );
        }
        if !self.init_conn().await {
            let reply = self
                .has_failed()
                .unwrap_or_else(|| "421 4.3.0 Try again later.".into());
            return refuse(reply, refused);
        }
        self.stream.tx_buf.clear();

        // EHLO
        let _ = self.handle_ehlo(Cow::Owned(helo), true).await;
        if let Some(reply) = self.has_failed() {
            return refuse(reply, refused);
        }

        // MAIL FROM
        let line = command("MAIL FROM", &mail_from);
        let mut receiver = RequestReceiver::default();
        let Ok(Request::Mail { from }) = receiver.ingest(&mut line.iter()) else {
            return refuse("501 5.5.4 Invalid MAIL FROM.".into(), refused);
        };
        lines.mail_from = Some(from.clone().into_owned());
        let _ = self.handle_mail_from(from).await;
        if let Some(reply) = self.has_failed() {
            return refuse(reply, refused);
        }

        // RCPT TO: the relay already checked each recipient (RL-1); this
        // server checks again, by its own directory and rules
        self.params.rcpt_errors_wait = Duration::ZERO;
        for (address, parameters) in rcpt_to {
            let line = command("RCPT TO", &(address.clone(), parameters));
            let mut receiver = RequestReceiver::default();
            let Ok(Request::Rcpt { mut to }) = receiver.ingest(&mut line.iter()) else {
                refused.push((address, "501 5.5.4 Invalid RCPT TO.".into()));
                continue;
            };
            if !self.params.rcpt_dsn {
                // The relay offers DSN to everyone; this server may not
                to.flags &= !(RCPT_NOTIFY_DELAY
                    | RCPT_NOTIFY_FAILURE
                    | RCPT_NOTIFY_NEVER
                    | RCPT_NOTIFY_SUCCESS);
                to.orcpt = None;
            }
            lines.rcpt_to.push(to.clone().into_owned());
            let _ = self.handle_rcpt_to(to).await;
            if let Some(reply) = self.has_failed() {
                refused.push((address, reply));
            }
        }
        if self.data.rcpt_to.is_empty() {
            // The reply the sender would have been given: a temporary one
            // if any recipient had one, so it tries again
            let reply = refused
                .iter()
                .map(|(_, reply)| reply)
                .find(|reply| reply.starts_with('4'))
                .or(refused.first().map(|(_, reply)| reply))
                .cloned()
                .unwrap_or_else(|| "554 5.5.1 No valid recipients.".into());
            return refuse(reply, refused);
        }

        // DATA
        if let Some(reply) = self.can_send_data().await {
            return refuse(reply_text(reply), refused);
        }
        if message.len() >= self.params.max_message_size {
            return refuse("552 5.3.4 Message too big for system.".into(), refused);
        }
        self.data.message = message;
        let reply = self.queue_message().await;
        let reply = reply_text(&reply);
        if reply.starts_with('2') {
            RelayedOutcome::Accepted { refused }
        } else {
            refuse(reply, refused)
        }
    }

    /// RL-18: a DSN for recipients refused after the relay had said 250,
    /// only when the sender passed SPF or DMARC here, so a forged sender
    /// gets none and the relay is no backscatter source.
    async fn bounce_held(&mut self, refused: &[(String, String)], lines: &Lines) {
        let Some(mail_from) = self.data.mail_from.as_ref() else {
            return;
        };
        let spf_pass = self
            .data
            .spf_mail_from
            .as_ref()
            .is_some_and(|spf| spf.result() == SpfResult::Pass);
        let dmarc_pass = self.data.relayed.as_ref().is_some_and(|r| r.dmarc_pass);
        if mail_from.address_lcase.is_empty() || !(spf_pass || dmarc_pass) {
            trc::event!(
                Delivery(trc::DeliveryEvent::DoubleBounce),
                SpanId = self.data.session_id,
                From = mail_from.address_lcase.clone(),
                Reason = "Held by a relay and refused here; the sender passed neither SPF nor DMARC, so no DSN.",
            );
            return;
        }

        let mut wrapper = self.server.new_message(
            mail_from.address.as_str(),
            MessageSource::Unauthenticated { dmarc_pass },
            self.data.session_id,
        );
        if let Some(from) = &lines.mail_from {
            wrapper.message.env_id = from.env_id.as_deref().map(Into::into);
            wrapper.message.flags |= from.flags & (MAIL_RET_FULL | MAIL_RET_HDRS);
        }
        wrapper.message.received_from_ip = self.data.remote_ip;
        wrapper.message.received_via_port = 25;
        for (address, reply) in refused {
            let line = lines
                .rcpt_to
                .iter()
                .find(|to| to.address.eq_ignore_ascii_case(address));
            let flags = line.map_or(0, |to| to.flags);
            let flags = if flags
                & (RCPT_NOTIFY_DELAY
                    | RCPT_NOTIFY_FAILURE
                    | RCPT_NOTIFY_NEVER
                    | RCPT_NOTIFY_SUCCESS)
                == 0
            {
                RCPT_NOTIFY_FAILURE
            } else {
                flags
            };
            let mut recipient = Recipient::new(address).with_flags(flags);
            recipient.orcpt = line.and_then(|to| to.orcpt.as_deref()).map(Into::into);
            recipient.status = Status::PermanentFailure(ErrorDetails {
                entity: self.hostname.as_str().into(),
                details: Error::UnexpectedResponse(UnexpectedResponse {
                    command: format!("RCPT TO:<{address}>").into_boxed_str(),
                    response: parse_response(reply),
                }),
            });
            wrapper.message.recipients.push(recipient);
        }

        // The DSN quotes the message's headers from the blob store
        let message = &self.data.message;
        let headers = &message[..header_end(message)];
        wrapper.message.blob_hash = BlobHash::generate(headers);
        wrapper.message.size = message.len() as u64;
        let mut batch = BatchBuilder::new();
        batch.set(
            BlobOp::Link {
                hash: wrapper.message.blob_hash.clone(),
                to: BlobLink::Temporary {
                    until: now() + DSN_HEADERS_FOR,
                },
            },
            vec![],
        );
        let stored = match self.server.store().write(batch.build_all()).await {
            Ok(_) => self
                .server
                .blob_store()
                .put_blob(
                    wrapper.message.blob_hash.as_slice(),
                    headers,
                    self.server.core.email.compression,
                )
                .await
                .map(|_| ()),
            Err(err) => Err(err),
        };
        if let Err(err) = stored {
            trc::error!(
                err.details("Failed to store a relayed message's headers for its DSN.")
                    .span_id(self.data.session_id)
                    .caused_by(trc::location!())
            );
            return;
        }
        self.server.send_dsn(&mut wrapper).await;
    }
}

/// `MAIL FROM:<address> KEY=value...` or the RCPT TO equivalent. Anything
/// that could end the line or start another parameter is dropped.
fn command(verb: &str, (address, parameters): &EnvelopeAddress) -> Vec<u8> {
    let clean = |text: &str| -> String {
        text.chars()
            .filter(|c| !c.is_control() && !matches!(c, ' ' | '<' | '>'))
            .collect()
    };
    let mut line = format!("{verb}:<{}>", clean(address));
    for (key, value) in parameters {
        let key: String = clean(key).replace('=', "");
        if key.is_empty() {
            continue;
        }
        line.push(' ');
        line.push_str(&key);
        if let Some(value) = value {
            line.push('=');
            line.push_str(&clean(value));
        }
    }
    line.push_str("\r\n");
    line.into_bytes()
}

/// A reply as text, its last line if it has several.
fn reply_text(reply: &[u8]) -> String {
    let text = String::from_utf8_lossy(reply);
    text.trim_end()
        .rsplit("\r\n")
        .next()
        .unwrap_or_default()
        .chars()
        .take(512)
        .collect::<String>()
        .trim()
        .to_string()
}

/// `550 5.1.1 text` as a response.
fn parse_response(reply: &str) -> Response<Box<str>> {
    let mut parts = reply.splitn(3, ' ');
    let code = parts.next().and_then(|c| c.parse().ok()).unwrap_or(550);
    let (esc, message) = match parts.next() {
        Some(esc) if enhanced(esc).is_some() => (
            enhanced(esc).unwrap_or([5, 0, 0]),
            parts.next().unwrap_or_default(),
        ),
        other => (
            [(code / 100) as u8, 0, 0],
            reply
                .split_once(' ')
                .map(|(_, rest)| rest)
                .filter(|_| other.is_some())
                .unwrap_or_default(),
        ),
    };
    Response {
        code,
        esc,
        message: message.into(),
    }
}

fn enhanced(text: &str) -> Option<[u8; 3]> {
    let mut parts = text.split('.').map(|p| p.parse::<u8>().ok());
    let esc = [parts.next()??, parts.next()??, parts.next()??];
    parts.next().is_none().then_some(esc)
}

/// Where the headers end: after the blank line, or the whole message.
fn header_end(message: &[u8]) -> usize {
    message
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(message.len(), |pos| pos + 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_commands() {
        let line = command(
            "RCPT TO",
            &(
                "jane@example.com".into(),
                vec![
                    ("NOTIFY".into(), Some("FAILURE,DELAY".into())),
                    ("ORCPT".into(), Some("rfc822;jane@example.com".into())),
                ],
            ),
        );
        assert_eq!(
            line,
            b"RCPT TO:<jane@example.com> NOTIFY=FAILURE,DELAY ORCPT=rfc822;jane@example.com\r\n"
        );
        let mut receiver = RequestReceiver::default();
        let Ok(Request::Rcpt { to }) = receiver.ingest(&mut line.iter()) else {
            panic!("not parsed");
        };
        assert_eq!(to.address, "jane@example.com");
        assert_ne!(to.flags & RCPT_NOTIFY_FAILURE, 0);

        // Nothing can end the line or add a parameter
        let line = command(
            "MAIL FROM",
            &(
                "a@b.c> AUTH=x\r\nRCPT TO:<z@y.x".into(),
                vec![("BODY=X ".into(), Some("8BIT MIME\r\n".into()))],
            ),
        );
        assert_eq!(
            line,
            b"MAIL FROM:<a@b.cAUTH=xRCPTTO:z@y.x> BODYX=8BITMIME\r\n"
        );
    }

    #[test]
    fn reads_replies() {
        assert_eq!(
            reply_text(b"550-5.7.1 First\r\n550 5.7.1 Message rejected.\r\n"),
            "550 5.7.1 Message rejected."
        );
        let response = parse_response("550 5.1.1 Mailbox unavailable");
        assert_eq!(
            (response.code, response.esc, response.message.as_ref()),
            (550, [5, 1, 1], "Mailbox unavailable")
        );
        let response = parse_response("451 try later");
        assert_eq!(
            (response.code, response.esc, response.message.as_ref()),
            (451, [4, 0, 0], "try later")
        );
        assert_eq!(header_end(b"A: b\r\n\r\nbody"), 8);
        assert_eq!(header_end(b"A: b"), 4);
    }
}
