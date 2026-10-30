/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! One SMTP client session to one address of one MX host (RFC 5321): the
//! greeting, EHLO, STARTTLS as the TLS mode asks, and one transaction.

use super::tls::{self, TlsMode, TlsOutcome};
use inbuxa_relay_proto::types::{Address, TlsInfo};
use std::{net::SocketAddr, path::Path, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// RFC 5321 §4.5.3.2 asks for five minutes for most replies.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
/// And ten for the reply to the final dot.
const DATA_TIMEOUT: Duration = Duration::from_secs(600);
const LINE_MAX: u64 = 4096;
const REPLY_LINES_MAX: usize = 100;

/// An SMTP reply, all its lines joined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub text: String,
}

impl Reply {
    pub fn class(&self) -> u16 {
        self.code / 100
    }

    /// As `deliveryStatus` shows it: `250 2.0.0 OK`.
    pub fn line(&self) -> String {
        if self.text.is_empty() {
            self.code.to_string()
        } else {
            format!("{} {}", self.code, self.text.replace('\n', " "))
        }
    }
}

/// What a session left each recipient with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RcptOutcome {
    Delivered(String),
    Refused(String),
    Deferred(String),
}

/// A session that couldn't reach a transaction: the next address or host
/// may do better. `tls` is set when a TLS policy failed, for TLS-RPT.
#[derive(Debug)]
pub struct HostFailure {
    pub reason: String,
    pub tls: Option<tls::TlsFailure>,
}

fn host_failure(reason: impl Into<String>) -> HostFailure {
    HostFailure {
        reason: reason.into(),
        tls: None,
    }
}

pub struct Session<'a> {
    pub addr: SocketAddr,
    /// The MX host, for SNI and certificate checks.
    pub mx: &'a str,
    /// The recipient domain, a DANE reference identifier too.
    pub domain: &'a str,
    /// This relay's name, for EHLO.
    pub helo: &'a str,
    pub mode: TlsMode,
    pub mail_from: &'a Address,
    pub rcpt_to: &'a [&'a Address],
    pub message: &'a Path,
    pub size: u64,
}

/// What came of a session that reached MAIL FROM.
#[derive(Debug)]
pub struct Delivered {
    pub outcomes: Vec<RcptOutcome>,
    pub tls: Option<TlsInfo>,
}

impl Session<'_> {
    pub async fn run(&self) -> Result<Delivered, HostFailure> {
        match self.attempt(self.mode.clone()).await {
            // Opportunistic TLS that fails to set up: once more in the
            // clear, as other MTAs do; nothing was promised.
            Err(HostFailure {
                tls: Some(failure), ..
            }) if self.mode == TlsMode::Opportunistic && failure.handshake => {
                self.attempt(TlsMode::None).await
            }
            other => other,
        }
    }

    async fn attempt(&self, mode: TlsMode) -> Result<Delivered, HostFailure> {
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(self.addr))
            .await
            .map_err(|_| host_failure(format!("Connection to {} timed out", self.mx)))?
            .map_err(|e| host_failure(format!("Connection to {} failed: {e}", self.mx)))?;
        let mut conn = BufReader::new(tcp);
        let greeting = read_reply(&mut conn, COMMAND_TIMEOUT).await?;
        if greeting.class() != 2 {
            return Err(host_failure(format!(
                "{} greeted with {}",
                self.mx,
                greeting.line()
            )));
        }
        let ehlo = self.ehlo(&mut conn).await?;
        let wants_tls = mode != TlsMode::None;
        if !ehlo.starttls {
            if mode.is_required() {
                return Err(HostFailure {
                    reason: format!("{} doesn't offer STARTTLS", self.mx),
                    tls: Some(tls::TlsFailure::starttls_not_supported()),
                });
            }
            return self.transaction(conn, &ehlo, None).await;
        }
        if !wants_tls {
            return self.transaction(conn, &ehlo, None).await;
        }
        command(&mut conn, "STARTTLS\r\n").await?;
        let reply = read_reply(&mut conn, COMMAND_TIMEOUT).await?;
        if reply.class() != 2 {
            return Err(HostFailure {
                reason: format!("{} refused STARTTLS: {}", self.mx, reply.line()),
                tls: mode
                    .is_required()
                    .then(tls::TlsFailure::starttls_not_supported),
            });
        }
        // Anything sent before the handshake would be read as if it had
        // come over TLS (CVE-2011-0411).
        if !conn.buffer().is_empty() {
            return Err(host_failure(format!(
                "{} sent data after accepting STARTTLS",
                self.mx
            )));
        }
        let TlsOutcome { stream, info } = tls::handshake(
            conn.into_inner(),
            self.mx,
            self.domain,
            &mode,
            COMMAND_TIMEOUT,
        )
        .await
        .map_err(|failure| HostFailure {
            reason: format!("TLS with {} failed: {}", self.mx, failure.reason),
            tls: Some(failure),
        })?;
        let mut conn = BufReader::new(stream);
        let ehlo = self.ehlo(&mut conn).await?;
        self.transaction(conn, &ehlo, Some(info)).await
    }

    async fn ehlo<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        conn: &mut BufReader<S>,
    ) -> Result<Ehlo, HostFailure> {
        command(conn, &format!("EHLO {}\r\n", self.helo)).await?;
        let reply = read_reply(conn, COMMAND_TIMEOUT).await?;
        if reply.class() != 2 {
            return Err(host_failure(format!(
                "{} refused EHLO: {}",
                self.mx,
                reply.line()
            )));
        }
        Ok(Ehlo::parse(&reply))
    }

    async fn transaction<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut conn: BufReader<S>,
        ehlo: &Ehlo,
        tls: Option<TlsInfo>,
    ) -> Result<Delivered, HostFailure> {
        let all = |outcome: fn(String) -> RcptOutcome, reply: String| Delivered {
            outcomes: self
                .rcpt_to
                .iter()
                .map(|_| outcome(reply.clone()))
                .collect(),
            tls: tls.clone(),
        };
        let needs_utf8 =
            !self.mail_from.email.is_ascii() || self.rcpt_to.iter().any(|r| !r.email.is_ascii());
        if needs_utf8 && !ehlo.smtputf8 {
            let _ = quit(&mut conn).await;
            return Ok(all(
                RcptOutcome::Refused,
                format!(
                    "553 5.6.7 {} doesn't accept internationalized addresses",
                    self.mx
                ),
            ));
        }
        if ehlo.size.is_some_and(|max| max > 0 && self.size > max) {
            let _ = quit(&mut conn).await;
            return Ok(all(
                RcptOutcome::Refused,
                format!("552 5.3.4 The message is larger than {} accepts", self.mx),
            ));
        }

        command(
            &mut conn,
            &mail_from(self.mail_from, ehlo, self.size, needs_utf8),
        )
        .await?;
        let reply = read_reply(&mut conn, COMMAND_TIMEOUT).await?;
        match reply.class() {
            2 => {}
            5 => {
                let _ = quit(&mut conn).await;
                return Ok(all(RcptOutcome::Refused, reply.line()));
            }
            _ => {
                let _ = quit(&mut conn).await;
                return Ok(all(RcptOutcome::Deferred, reply.line()));
            }
        }

        let mut outcomes = Vec::with_capacity(self.rcpt_to.len());
        let mut accepted = Vec::new();
        for (i, rcpt) in self.rcpt_to.iter().enumerate() {
            command(&mut conn, &rcpt_to(rcpt, ehlo)).await?;
            let reply = read_reply(&mut conn, COMMAND_TIMEOUT).await?;
            outcomes.push(match reply.class() {
                2 => {
                    accepted.push(i);
                    RcptOutcome::Delivered(reply.line())
                }
                5 => RcptOutcome::Refused(reply.line()),
                _ => RcptOutcome::Deferred(reply.line()),
            });
        }
        if accepted.is_empty() {
            let _ = quit(&mut conn).await;
            return Ok(Delivered { outcomes, tls });
        }

        command(&mut conn, "DATA\r\n").await?;
        let reply = read_reply(&mut conn, COMMAND_TIMEOUT).await?;
        let final_reply = if reply.code == 354 {
            send_message(&mut conn, self.message)
                .await
                .map_err(|e| host_failure(format!("Sending to {} failed: {e}", self.mx)))?;
            read_reply(&mut conn, DATA_TIMEOUT).await?
        } else {
            reply
        };
        for i in accepted {
            outcomes[i] = match final_reply.class() {
                2 => RcptOutcome::Delivered(final_reply.line()),
                5 => RcptOutcome::Refused(final_reply.line()),
                _ => RcptOutcome::Deferred(final_reply.line()),
            };
        }
        let _ = quit(&mut conn).await;
        Ok(Delivered { outcomes, tls })
    }
}

/// What the server's EHLO reply offers.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Ehlo {
    pub starttls: bool,
    pub size: Option<u64>,
    pub eight_bit: bool,
    pub smtputf8: bool,
    pub dsn: bool,
}

impl Ehlo {
    fn parse(reply: &Reply) -> Ehlo {
        let mut ehlo = Ehlo::default();
        // The first line is the greeting; the rest are keywords.
        for line in reply.text.split('\n').skip(1) {
            let mut words = line.split_ascii_whitespace();
            let Some(keyword) = words.next() else {
                continue;
            };
            match keyword.to_ascii_uppercase().as_str() {
                "STARTTLS" => ehlo.starttls = true,
                "SIZE" => ehlo.size = Some(words.next().and_then(|n| n.parse().ok()).unwrap_or(0)),
                "8BITMIME" => ehlo.eight_bit = true,
                "SMTPUTF8" => ehlo.smtputf8 = true,
                "DSN" => ehlo.dsn = true,
                _ => {}
            }
        }
        ehlo
    }
}

/// The value of an SMTP parameter, if the downstream gave it.
fn parameter<'a>(address: &'a Address, name: &str) -> Option<Option<&'a str>> {
    address
        .parameters
        .as_ref()?
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_deref())
}

/// MAIL FROM, with only the parameters this server takes (RFC 1870, 6152,
/// 6531, 3461). The size is the relay's own count.
fn mail_from(from: &Address, ehlo: &Ehlo, size: u64, utf8: bool) -> String {
    let mut line = format!("MAIL FROM:<{}>", from.email);
    if ehlo.size.is_some() {
        line.push_str(&format!(" SIZE={size}"));
    }
    if ehlo.eight_bit
        && let Some(Some(body)) = parameter(from, "BODY")
        && body.eq_ignore_ascii_case("8BITMIME")
    {
        line.push_str(" BODY=8BITMIME");
    }
    if utf8 {
        line.push_str(" SMTPUTF8");
    }
    if ehlo.dsn {
        for name in ["RET", "ENVID"] {
            if let Some(Some(value)) = parameter(from, name) {
                line.push_str(&format!(" {name}={value}"));
            }
        }
    }
    line.push_str("\r\n");
    line
}

fn rcpt_to(rcpt: &Address, ehlo: &Ehlo) -> String {
    let mut line = format!("RCPT TO:<{}>", rcpt.email);
    if ehlo.dsn {
        for name in ["NOTIFY", "ORCPT"] {
            if let Some(Some(value)) = parameter(rcpt, name) {
                line.push_str(&format!(" {name}={value}"));
            }
        }
    }
    line.push_str("\r\n");
    line
}

async fn command<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut BufReader<S>,
    line: &str,
) -> Result<(), HostFailure> {
    let stream = conn.get_mut();
    tokio::time::timeout(COMMAND_TIMEOUT, async {
        stream.write_all(line.as_bytes()).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| host_failure("The server stopped reading"))?
    .map_err(|e| host_failure(format!("The connection dropped: {e}")))
}

async fn quit<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut BufReader<S>,
) -> Result<(), HostFailure> {
    command(conn, "QUIT\r\n").await?;
    tokio::time::timeout(Duration::from_secs(10), read_reply(conn, COMMAND_TIMEOUT))
        .await
        .map_err(|_| host_failure("no reply to QUIT"))?
        .map(|_| ())
}

/// One reply, multi-line or not; the lines after the first are joined
/// with `\n`, so EHLO can read them.
pub async fn read_reply<S: AsyncRead + Unpin>(
    conn: &mut BufReader<S>,
    timeout: Duration,
) -> Result<Reply, HostFailure> {
    tokio::time::timeout(timeout, read_reply_inner(conn))
        .await
        .map_err(|_| host_failure("The server didn't answer in time"))?
}

async fn read_reply_inner<S: AsyncRead + Unpin>(
    conn: &mut BufReader<S>,
) -> Result<Reply, HostFailure> {
    let mut code = None;
    let mut lines: Vec<String> = Vec::new();
    loop {
        let mut raw = Vec::new();
        (&mut *conn)
            .take(LINE_MAX)
            .read_until(b'\n', &mut raw)
            .await
            .map_err(|e| host_failure(format!("The connection dropped: {e}")))?;
        if raw.is_empty() {
            return Err(host_failure("The server closed the connection"));
        }
        if raw.last() != Some(&b'\n') {
            return Err(host_failure("The server sent a line that is too long"));
        }
        let line = String::from_utf8_lossy(&raw);
        let line = line.trim_end_matches(['\r', '\n']);
        let this_code = line
            .get(..3)
            .and_then(|c| c.parse::<u16>().ok())
            .filter(|c| (200..600).contains(c))
            .ok_or_else(|| host_failure("The server sent something that isn't a reply"))?;
        if code.is_some_and(|c| c != this_code) {
            return Err(host_failure("The server mixed reply codes in one reply"));
        }
        code = Some(this_code);
        let rest = line.get(4..).unwrap_or("");
        lines.push(rest.replace(|c: char| c.is_control(), " "));
        let last = line.as_bytes().get(3) != Some(&b'-');
        if last {
            return Ok(Reply {
                code: this_code,
                text: lines.join("\n"),
            });
        }
        if lines.len() >= REPLY_LINES_MAX {
            return Err(host_failure("The server's reply is too long"));
        }
    }
}

/// The message as stored, dot-stuffed (RFC 5321 §4.5.2), then the final
/// dot. Its bytes are otherwise sent as they are: the downstream signed
/// them.
async fn send_message<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut BufReader<S>,
    path: &Path,
) -> std::io::Result<()> {
    let mut file = tokio::fs::File::open(path).await?;
    let stream = conn.get_mut();
    let mut buf = vec![0u8; 64 * 1024];
    let mut out = Vec::with_capacity(buf.len() + 1024);
    let mut stuffer = DotStuffer::default();
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        out.clear();
        stuffer.push(&buf[..n], &mut out);
        tokio::time::timeout(COMMAND_TIMEOUT, stream.write_all(&out))
            .await
            .map_err(|_| std::io::Error::other("the server stopped reading"))??;
    }
    out.clear();
    stuffer.finish(&mut out);
    stream.write_all(&out).await?;
    stream.flush().await
}

/// Doubles a dot that starts a line, across chunk boundaries.
struct DotStuffer {
    at_line_start: bool,
    last: Option<u8>,
}

impl Default for DotStuffer {
    fn default() -> Self {
        DotStuffer {
            at_line_start: true,
            last: None,
        }
    }
}

impl DotStuffer {
    fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        for &b in chunk {
            if self.at_line_start && b == b'.' {
                out.push(b'.');
            }
            out.push(b);
            self.at_line_start = b == b'\n';
            self.last = Some(b);
        }
    }

    fn finish(&self, out: &mut Vec<u8>) {
        match self.last {
            Some(b'\n') | None => {}
            Some(b'\r') => out.push(b'\n'),
            Some(_) => out.extend_from_slice(b"\r\n"),
        }
        out.extend_from_slice(b".\r\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stuff(chunks: &[&[u8]]) -> Vec<u8> {
        let mut s = DotStuffer::default();
        let mut out = Vec::new();
        for c in chunks {
            s.push(c, &mut out);
        }
        s.finish(&mut out);
        out
    }

    #[test]
    fn dots_are_stuffed_across_chunks() {
        assert_eq!(
            stuff(&[b".a\r\nb\r", b"\n.c\r\n"]),
            b"..a\r\nb\r\n..c\r\n.\r\n"
        );
        assert_eq!(stuff(&[b"a\r\n", b".\r\n"]), b"a\r\n..\r\n.\r\n");
        assert_eq!(stuff(&[b"no end"]), b"no end\r\n.\r\n");
        assert_eq!(stuff(&[b"x\r"]), b"x\r\n.\r\n");
    }

    #[tokio::test]
    async fn replies_parse() {
        let mut r = BufReader::new(
            &b"250-mx.example.org hi\r\n250-SIZE 1000\r\n250-starttls\r\n250 DSN\r\n"[..],
        );
        let reply = read_reply_inner(&mut r).await.unwrap();
        assert_eq!(reply.code, 250);
        let ehlo = Ehlo::parse(&reply);
        assert!(ehlo.starttls && ehlo.dsn && !ehlo.smtputf8);
        assert_eq!(ehlo.size, Some(1000));

        let mut r = BufReader::new(&b"550 5.1.1 no\x07 such user\r\n"[..]);
        assert_eq!(
            read_reply_inner(&mut r).await.unwrap().line(),
            "550 5.1.1 no  such user"
        );
        for bad in [
            &b"250-a\r\n251 b\r\n"[..],
            b"hello\r\n",
            b"250-a\r\n",
            b"099 x\r\n",
        ] {
            let mut r = BufReader::new(bad);
            assert!(read_reply_inner(&mut r).await.is_err(), "{bad:?}");
        }
    }

    #[test]
    fn only_offered_parameters_are_sent() {
        let mut from = Address::new("a@example.com");
        from.parameters = Some(
            [
                ("BODY".to_string(), Some("8BITMIME".to_string())),
                ("RET".to_string(), Some("HDRS".to_string())),
                ("AUTH".to_string(), Some("x".to_string())),
            ]
            .into(),
        );
        let bare = Ehlo::default();
        assert_eq!(
            mail_from(&from, &bare, 10, false),
            "MAIL FROM:<a@example.com>\r\n"
        );
        let full = Ehlo {
            size: Some(0),
            eight_bit: true,
            dsn: true,
            ..Default::default()
        };
        assert_eq!(
            mail_from(&from, &full, 10, true),
            "MAIL FROM:<a@example.com> SIZE=10 BODY=8BITMIME SMTPUTF8 RET=HDRS\r\n"
        );
        let mut rcpt = Address::new("b@example.org");
        rcpt.parameters = Some([("NOTIFY".to_string(), Some("NEVER".to_string()))].into());
        assert_eq!(rcpt_to(&rcpt, &bare), "RCPT TO:<b@example.org>\r\n");
        assert_eq!(
            rcpt_to(&rcpt, &full),
            "RCPT TO:<b@example.org> NOTIFY=NEVER\r\n"
        );
    }
}
