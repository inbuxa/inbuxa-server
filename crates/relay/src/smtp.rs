/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The door: SMTP on port 25 (spec "Inbound").
//!
//! It takes mail only for the downstream's real recipients (RL-1), offers
//! no AUTH and no relaying (RL-4), seals each message to the spool as it
//! arrives (RL-21), and in live mode holds its answer until the downstream
//! gives a verdict (RL-12, RL-13). The relay adds no header: the downstream
//! writes the trace from the session facts it is given.

use crate::{
    app::App,
    events::data,
    spool::{Incoming, Meta},
};
use inbuxa_relay_proto::{
    recipient::Lookup,
    time,
    types::{
        Address, Envelope, Mode, RelaySettings, Session as SessionFacts, SmtpCertificate, TlsInfo,
        Verdict,
    },
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde_json::json;
use smtp_proto::{
    Error as ParseError, MAIL_BODY_7BIT, MAIL_BODY_8BITMIME, MAIL_BODY_BINARYMIME, MAIL_REQUIRETLS,
    MAIL_RET_FULL, MAIL_RET_HDRS, MAIL_SMTPUTF8, MailFrom, RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE,
    RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS, RcptTo, Request,
    request::receiver::{DataReceiver, RequestReceiver},
};
use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
const DATA_TIMEOUT: Duration = Duration::from_secs(600);
const GREET_PAUSE: Duration = Duration::from_millis(300);
const MAX_ERRORS: u32 = 10;

/// The STARTTLS config for port 25: the downstream's certificate, or a
/// self-signed one for the hostname until it sends one. Senders accept a
/// self-signed certificate opportunistically, as they do any.
pub fn tls_config(
    hostname: &str,
    cert: Option<&SmtpCertificate>,
) -> Result<rustls::ServerConfig, String> {
    let (chain, key) = match cert {
        Some(cert) => {
            let chain: Vec<CertificateDer<'static>> =
                CertificateDer::pem_slice_iter(cert.chain_pem.as_bytes())
                    .collect::<Result<_, _>>()
                    .map_err(|e| format!("certificate chain: {e}"))?;
            if chain.is_empty() {
                return Err("the certificate chain is empty".into());
            }
            let key = PrivateKeyDer::from_pem_slice(cert.key_pem.as_bytes())
                .map_err(|e| format!("private key: {e}"))?;
            (chain, key)
        }
        None => {
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
                .map_err(|e| e.to_string())?;
            let cert = rcgen::CertificateParams::new(vec![hostname.to_string()])
                .and_then(|p| p.self_signed(&key))
                .map_err(|e| e.to_string())?;
            (
                vec![cert.der().clone()],
                PrivateKeyDer::try_from(key.serialize_der()).map_err(|e| e.to_string())?,
            )
        }
    };
    rustls::ServerConfig::builder_with_provider(crate::link::tls::provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| e.to_string())
}

/// The STARTTLS config, rebuilt when the settings change.
#[derive(Default)]
struct TlsCache {
    current: Mutex<Option<(String, Arc<rustls::ServerConfig>)>>,
}

impl TlsCache {
    fn get(&self, settings: &RelaySettings) -> Option<Arc<rustls::ServerConfig>> {
        let key = format!(
            "{}|{}",
            settings.hostname,
            settings
                .smtp_certificate
                .as_ref()
                .map_or("", |c| c.chain_pem.as_str())
        );
        let mut current = self.current.lock().expect("tls cache");
        if let Some((k, config)) = current.as_ref()
            && *k == key
        {
            return Some(config.clone());
        }
        match tls_config(&settings.hostname, settings.smtp_certificate.as_ref()) {
            Ok(config) => {
                let config = Arc::new(config);
                *current = Some((key, config.clone()));
                Some(config)
            }
            Err(e) => {
                eprintln!("inbuxa-relay: STARTTLS is off: {e}");
                None
            }
        }
    }
}

/// Keeps port 25 listening on the configured addresses while the relay is
/// configured, and closed otherwise.
pub async fn serve(app: Arc<App>) {
    let tls = Arc::new(TlsCache::default());
    let mut listeners: HashMap<SocketAddr, JoinHandle<()>> = HashMap::new();
    let mut settings_rx = app.settings.subscribe();
    loop {
        let wanted: Vec<SocketAddr> = match (app.mode(), app.settings()) {
            (Mode::Unconfigured, _) | (_, None) => vec![],
            (_, Some(s)) => s
                .smtp_listen
                .iter()
                .filter_map(|a| a.parse().ok())
                .collect(),
        };
        listeners.retain(|addr, task| {
            let keep = wanted.contains(addr) && !task.is_finished();
            if !keep {
                task.abort();
                eprintln!("inbuxa-relay: port 25 closed on {addr}");
            }
            keep
        });
        for addr in wanted {
            if listeners.contains_key(&addr) {
                continue;
            }
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    eprintln!("inbuxa-relay: SMTP listening on {addr}");
                    let app = app.clone();
                    let tls = tls.clone();
                    listeners.insert(addr, tokio::spawn(accept_loop(app, tls, listener)));
                }
                Err(e) => app.set_error(format!("could not listen on {addr}: {e}")),
            }
        }
        // Settings changes come by watch; the recipient set and the mode
        // are checked every few seconds.
        let _ = tokio::time::timeout(Duration::from_secs(3), settings_rx.changed()).await;
    }
}

async fn accept_loop(app: Arc<App>, tls: Arc<TlsCache>, listener: TcpListener) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let app = app.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            handle_connection(app, tls, tcp, peer).await;
        });
    }
}

async fn handle_connection(
    app: Arc<App>,
    tls: Arc<TlsCache>,
    mut tcp: TcpStream,
    peer: SocketAddr,
) {
    let Some(settings) = app.settings() else {
        return;
    };
    let local = tcp.local_addr().unwrap_or(peer);
    let allowed = app
        .limiter
        .lock()
        .expect("limiter")
        .connect(peer.ip(), &settings, time::now());
    if !allowed {
        let _ = tcp
            .write_all(b"421 4.7.0 Too many connections, try again later\r\n")
            .await;
        return;
    }
    // An early talker sends before the greeting: not a real MTA.
    let mut peek = [0u8; 1];
    if let Ok(Ok(n)) = tokio::time::timeout(GREET_PAUSE, tcp.peek(&mut peek)).await
        && n > 0
    {
        let _ = tcp.write_all(b"554 5.5.1 Wait for the greeting\r\n").await;
        app.limiter.lock().expect("limiter").disconnect(peer.ip());
        return;
    }
    let mut session = Session::new(app.clone(), settings.clone(), peer, local);
    let banner = format!("220 {} ESMTP\r\n", settings.hostname);
    if tcp.write_all(banner.as_bytes()).await.is_ok() {
        match session.run(tcp, None).await {
            End::StartTls(tcp) => {
                let config = tls.get(&settings);
                if let Some(config) = config {
                    match tokio::time::timeout(
                        Duration::from_secs(30),
                        TlsAcceptor::from(config).accept(tcp),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => {
                            let (_, conn) = stream.get_ref();
                            let info = TlsInfo {
                                version: conn
                                    .protocol_version()
                                    .map_or("unknown".into(), |v| format!("{v:?}")),
                                cipher: conn
                                    .negotiated_cipher_suite()
                                    .map_or("unknown".into(), |c| format!("{:?}", c.suite())),
                            };
                            session.reset_after_tls(info);
                            session.run(stream, None).await;
                        }
                        _ => session.tls_failed = true,
                    }
                }
            }
            End::Closed => {}
        }
    }
    app.limiter.lock().expect("limiter").disconnect(peer.ip());
    session.record_end();
}

enum End<S> {
    Closed,
    StartTls(S),
}

/// A command, owned, so it outlives the read buffer.
enum Cmd {
    Ehlo(String),
    Helo(String),
    Mail(MailFrom<String>),
    Rcpt(RcptTo<String>),
    Data,
    Rset,
    Noop,
    Quit,
    Help,
    Vrfy,
    StartTls,
    NotOffered,
}

impl Cmd {
    fn from(req: Request<std::borrow::Cow<'_, str>>) -> Cmd {
        match req {
            Request::Ehlo { host } => Cmd::Ehlo(host.into_owned()),
            Request::Helo { host } => Cmd::Helo(host.into_owned()),
            Request::Mail { from } => Cmd::Mail(from.into_owned()),
            Request::Rcpt { to } => Cmd::Rcpt(to.into_owned()),
            Request::Data => Cmd::Data,
            Request::Rset => Cmd::Rset,
            Request::Noop { .. } => Cmd::Noop,
            Request::Quit => Cmd::Quit,
            Request::Help { .. } => Cmd::Help,
            Request::Vrfy { .. } => Cmd::Vrfy,
            Request::StartTls => Cmd::StartTls,
            // No AUTH, no ETRN or ATRN, no BDAT, BURL, EXPN or LHLO.
            _ => Cmd::NotOffered,
        }
    }
}

struct Session {
    app: Arc<App>,
    settings: Arc<RelaySettings>,
    peer: SocketAddr,
    local: SocketAddr,
    helo: Option<String>,
    tls: Option<TlsInfo>,
    tls_failed: bool,
    mail_from: Option<Address>,
    rcpt_to: Vec<Address>,
    errors: u32,
    accepted: u32,
    refused_rcpts: u32,
    out: Vec<u8>,
}

enum Next {
    Continue,
    Close,
    StartTls,
    Data(Box<Incoming>),
}

struct DataState {
    rx: DataReceiver,
    incoming: Option<Box<Incoming>>,
    buf: Vec<u8>,
    too_big: bool,
}

impl Session {
    fn new(
        app: Arc<App>,
        settings: Arc<RelaySettings>,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Self {
        Session {
            app,
            settings,
            peer,
            local,
            helo: None,
            tls: None,
            tls_failed: false,
            mail_from: None,
            rcpt_to: Vec::new(),
            errors: 0,
            accepted: 0,
            refused_rcpts: 0,
            out: Vec::with_capacity(512),
        }
    }

    fn reset_after_tls(&mut self, info: TlsInfo) {
        self.tls = Some(info);
        self.helo = None;
        self.reset();
    }

    fn reset(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
    }

    fn reply(&mut self, line: &str) {
        self.out.extend_from_slice(line.as_bytes());
        self.out.extend_from_slice(b"\r\n");
    }

    fn error(&mut self, line: &str) {
        self.errors += 1;
        self.reply(line);
    }

    async fn flush<S: AsyncWrite + Unpin>(&mut self, stream: &mut S) -> std::io::Result<()> {
        if !self.out.is_empty() {
            stream.write_all(&self.out).await?;
            stream.flush().await?;
            self.out.clear();
        }
        Ok(())
    }

    async fn run<S: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        mut stream: S,
        _: Option<()>,
    ) -> End<S> {
        let mut buf = vec![0u8; 8192];
        let mut receiver = RequestReceiver::default();
        let mut data: Option<DataState> = None;
        loop {
            let timeout = if data.is_some() {
                DATA_TIMEOUT
            } else {
                COMMAND_TIMEOUT
            };
            let n = match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => break,
                Ok(Ok(n)) => n,
                Err(_) => {
                    self.reply("421 4.4.2 Timeout, closing");
                    let _ = self.flush(&mut stream).await;
                    break;
                }
            };
            let mut iter = buf[..n].iter();
            loop {
                if let Some(state) = data.as_mut() {
                    let done = state.rx.ingest(&mut iter, &mut state.buf);
                    if let Err(e) = self.take_data(state, done).await {
                        self.app
                            .set_error(format!("could not write to the spool: {e}"));
                        if let Some(incoming) = state.incoming.take() {
                            incoming.abort().await;
                        }
                        state.too_big = false;
                        self.reply("451 4.3.0 Temporary failure, try again later");
                        // Discard the rest of the message.
                        if !done {
                            break;
                        }
                    }
                    if !done {
                        break;
                    }
                    let state = data.take().expect("data");
                    self.end_of_data(state).await;
                    continue;
                }
                let cmd = match receiver.ingest(&mut iter) {
                    Ok(req) => Ok(Cmd::from(req)),
                    Err(ParseError::NeedsMoreData { .. }) => break,
                    Err(e) => Err(e),
                };
                let next = match cmd {
                    Ok(cmd) => self.command(cmd).await,
                    Err(e) => {
                        self.parse_error(e);
                        Next::Continue
                    }
                };
                match next {
                    Next::Continue => {}
                    Next::Close => {
                        let _ = self.flush(&mut stream).await;
                        return End::Closed;
                    }
                    Next::StartTls => {
                        // Anything pipelined after STARTTLS is dropped.
                        if self.flush(&mut stream).await.is_err() {
                            return End::Closed;
                        }
                        return End::StartTls(stream);
                    }
                    Next::Data(incoming) => {
                        data = Some(DataState {
                            rx: DataReceiver::new(),
                            incoming: Some(incoming),
                            buf: Vec::with_capacity(64 * 1024),
                            too_big: false,
                        });
                        // The 354 goes out now; the sender waits for it.
                        if self.flush(&mut stream).await.is_err() {
                            break;
                        }
                    }
                }
                if self.errors >= MAX_ERRORS {
                    self.reply("421 4.7.0 Too many errors, closing");
                    let _ = self.flush(&mut stream).await;
                    return End::Closed;
                }
            }
            if self.flush(&mut stream).await.is_err() {
                break;
            }
        }
        if let Some(mut state) = data
            && let Some(incoming) = state.incoming.take()
        {
            incoming.abort().await;
        }
        End::Closed
    }

    /// Moves received message bytes to the sealer. A byte is held back
    /// until the end is known: the end of data takes back the last CR.
    async fn take_data(&mut self, state: &mut DataState, done: bool) -> std::io::Result<()> {
        let keep = if done { 0 } else { 1.min(state.buf.len()) };
        let ready = state.buf.len() - keep;
        if ready == 0 {
            return Ok(());
        }
        if !state.too_big
            && let Some(incoming) = state.incoming.as_mut()
        {
            if incoming.size() + ready as u64 > self.settings.max_message_size {
                state.too_big = true;
            } else {
                incoming.write(&state.buf[..ready]).await?;
            }
        }
        state.buf.drain(..ready);
        Ok(())
    }

    async fn end_of_data(&mut self, mut state: DataState) {
        let Some(incoming) = state.incoming.take() else {
            // The spool failed mid-message; the 451 is already out.
            self.reset();
            return;
        };
        if state.too_big {
            incoming.abort().await;
            self.reset();
            self.reply("552 5.3.4 Message too big");
            return;
        }
        let size = incoming.size();
        let (id, file_len) = match incoming.finish().await {
            Ok(done) => done,
            Err(e) => {
                self.app
                    .set_error(format!("could not write to the spool: {e}"));
                self.reset();
                self.reply("451 4.3.0 Temporary failure, try again later");
                return;
            }
        };
        let meta = Meta {
            id: id.clone(),
            received_at: time::now(),
            envelope: Envelope {
                mail_from: self.mail_from.take().unwrap_or_else(|| Address::new("")),
                rcpt_to: std::mem::take(&mut self.rcpt_to),
            },
            session: SessionFacts {
                remote_ip: self.peer.ip(),
                remote_port: self.peer.port(),
                local_ip: self.local.ip(),
                helo: self.helo.clone().unwrap_or_default(),
                tls: self.tls.clone(),
                ptr: None,
            },
            size,
            door_checks: vec![],
        };
        let dir = self.app.paths.spool_in();
        let committed = {
            let (dir, meta) = (dir.clone(), meta.clone());
            tokio::task::spawn_blocking(move || crate::spool::Spool::commit_meta(&dir, &meta))
                .await
                .unwrap_or_else(|e| Err(std::io::Error::other(e)))
        };
        if let Err(e) = committed {
            let _ = tokio::fs::remove_file(dir.join(format!("{id}.msg"))).await;
            self.app
                .set_error(format!("could not write to the spool: {e}"));
            self.reply("451 4.3.0 Temporary failure, try again later");
            return;
        }
        // The message is on disk: from here the sender may be told 250.
        let live = self.app.mode() == Mode::Live;
        let waiter = self
            .app
            .spool
            .lock()
            .expect("spool")
            .insert(meta, file_len, live);
        self.app.inbound_changed();
        self.accepted += 1;
        let verdict = match waiter {
            Some(rx) => {
                let wait = Duration::from_secs(u64::from(self.settings.live_verdict_timeout));
                match tokio::time::timeout(wait, rx).await {
                    Ok(Ok(verdict)) => Some(verdict),
                    Ok(Err(_)) => None,
                    Err(_) => {
                        // RL-13: accept and hold.
                        self.app.spool.lock().expect("spool").stop_waiting(&id);
                        self.app.inbound_changed();
                        None
                    }
                }
            }
            None => None,
        };
        let mode = if live { "live" } else { "held" };
        match verdict {
            Some(Verdict::Reject(r)) | Some(Verdict::Tempfail(r)) => {
                self.accepted -= 1;
                self.app.record(
                    "inbound.refused",
                    data([("id", json!(id)), ("code", json!(r.code))]),
                );
                self.reply(&format!("{} {} {}", r.code, r.enhanced, r.text));
            }
            Some(Verdict::Accept) => {
                self.app.record(
                    "inbound.accepted",
                    data([
                        ("id", json!(id)),
                        ("mode", json!("live")),
                        ("size", json!(size)),
                    ]),
                );
                self.reply(&format!("250 2.0.0 Accepted {id}"));
            }
            None => {
                self.app.record(
                    "inbound.accepted",
                    data([
                        ("id", json!(id)),
                        ("mode", json!(mode)),
                        ("held", json!(true)),
                        ("size", json!(size)),
                    ]),
                );
                self.reply(&format!("250 2.0.0 Accepted {id}"));
            }
        }
    }

    fn parse_error(&mut self, e: ParseError) {
        let line = match e {
            ParseError::UnknownCommand => "500 5.5.1 Unknown command",
            ParseError::InvalidSenderAddress => "501 5.1.7 Bad sender address",
            ParseError::InvalidRecipientAddress => "501 5.1.3 Bad recipient address",
            ParseError::SyntaxError { .. } | ParseError::InvalidParameter { .. } => {
                "501 5.5.4 Syntax error"
            }
            ParseError::UnsupportedParameter { .. } => "504 5.5.4 Parameter not supported",
            ParseError::ResponseTooLong => "500 5.5.6 Line too long",
            _ => "500 5.5.2 Syntax error",
        };
        self.error(line);
    }

    async fn command(&mut self, cmd: Cmd) -> Next {
        match cmd {
            Cmd::Ehlo(host) => {
                self.reset();
                self.helo = Some(host);
                let mut lines = vec![
                    self.settings.hostname.clone(),
                    "PIPELINING".into(),
                    format!("SIZE {}", self.settings.max_message_size),
                    "8BITMIME".into(),
                    "ENHANCEDSTATUSCODES".into(),
                    "SMTPUTF8".into(),
                    "DSN".into(),
                ];
                if self.tls.is_none() && !self.tls_failed {
                    lines.push("STARTTLS".into());
                }
                let last = lines.len() - 1;
                for (i, line) in lines.iter().enumerate() {
                    let sep = if i == last { ' ' } else { '-' };
                    self.reply(&format!("250{sep}{line}"));
                }
            }
            Cmd::Helo(host) => {
                self.reset();
                self.helo = Some(host);
                let line = format!("250 {}", self.settings.hostname);
                self.reply(&line);
            }
            Cmd::StartTls => {
                if self.tls.is_some() {
                    self.error("503 5.5.1 Already in TLS");
                } else {
                    self.reply("220 2.0.0 Ready to start TLS");
                    return Next::StartTls;
                }
            }
            Cmd::Mail(from) => self.mail(from),
            Cmd::Rcpt(to) => self.rcpt(to),
            Cmd::Data => return self.data().await,
            Cmd::Rset => {
                self.reset();
                self.reply("250 2.0.0 OK");
            }
            Cmd::Noop => self.reply("250 2.0.0 OK"),
            Cmd::Quit => {
                self.reply("221 2.0.0 Bye");
                return Next::Close;
            }
            Cmd::Help => self.reply("214 2.0.0 See RFC 5321"),
            Cmd::Vrfy => self.reply("252 2.5.0 Cannot verify, but will accept the message"),
            Cmd::NotOffered => self.error("502 5.5.1 Command not offered"),
        }
        Next::Continue
    }

    fn mail(&mut self, from: MailFrom<String>) {
        if self.helo.is_none() {
            return self.error("503 5.5.1 Say EHLO first");
        }
        if self.mail_from.is_some() {
            return self.error("503 5.5.1 A transaction is already open");
        }
        if self.settings.max_message_size > 0 && from.size as u64 > self.settings.max_message_size {
            return self.reply("552 5.3.4 Message too big");
        }
        if self.app.spool_full(&self.settings) {
            return self.reply("452 4.3.1 Insufficient storage, try again later");
        }
        let allowed = self.app.limiter.lock().expect("limiter").message(
            self.peer.ip(),
            &self.settings,
            time::now(),
        );
        if !allowed {
            return self.reply("450 4.7.0 Too many messages, try again later");
        }
        let mut params = BTreeMap::new();
        if from.size > 0 {
            params.insert("SIZE".into(), Some(from.size.to_string()));
        }
        let body = if from.flags & MAIL_BODY_BINARYMIME != 0 {
            Some("BINARYMIME")
        } else if from.flags & MAIL_BODY_8BITMIME != 0 {
            Some("8BITMIME")
        } else if from.flags & MAIL_BODY_7BIT != 0 {
            Some("7BIT")
        } else {
            None
        };
        if let Some(body) = body {
            params.insert("BODY".into(), Some(body.into()));
        }
        if from.flags & MAIL_SMTPUTF8 != 0 {
            params.insert("SMTPUTF8".into(), None);
        }
        if from.flags & MAIL_REQUIRETLS != 0 {
            params.insert("REQUIRETLS".into(), None);
        }
        if from.flags & MAIL_RET_FULL != 0 {
            params.insert("RET".into(), Some("FULL".into()));
        } else if from.flags & MAIL_RET_HDRS != 0 {
            params.insert("RET".into(), Some("HDRS".into()));
        }
        if let Some(env_id) = from.env_id {
            params.insert("ENVID".into(), Some(env_id));
        }
        self.mail_from = Some(Address {
            email: from.address,
            parameters: (!params.is_empty()).then_some(params),
        });
        self.reply("250 2.1.0 OK");
    }

    fn rcpt(&mut self, to: RcptTo<String>) {
        if self.mail_from.is_none() {
            return self.error("503 5.5.1 MAIL first");
        }
        if self.rcpt_to.len() as u32 >= self.settings.max_recipients {
            return self.reply("452 4.5.3 Too many recipients");
        }
        if self
            .rcpt_to
            .iter()
            .any(|a| a.email.eq_ignore_ascii_case(&to.address))
        {
            return self.reply("250 2.1.5 OK");
        }
        let Some(key) = self.settings.recipient_key else {
            return self.reply("451 4.3.0 Not ready, try again later");
        };
        let settings = self.settings.clone();
        let lookup =
            self.app
                .recipients
                .read()
                .expect("recipients")
                .lookup(&to.address, &key, |d| settings.serves(d));
        match lookup {
            Lookup::Accept => {
                let mut params = BTreeMap::new();
                let notify: Vec<&str> = [
                    (RCPT_NOTIFY_SUCCESS, "SUCCESS"),
                    (RCPT_NOTIFY_FAILURE, "FAILURE"),
                    (RCPT_NOTIFY_DELAY, "DELAY"),
                ]
                .into_iter()
                .filter(|(flag, _)| to.flags & flag != 0)
                .map(|(_, name)| name)
                .collect();
                if to.flags & RCPT_NOTIFY_NEVER != 0 {
                    params.insert("NOTIFY".into(), Some("NEVER".into()));
                } else if !notify.is_empty() {
                    params.insert("NOTIFY".into(), Some(notify.join(",")));
                }
                if let Some(orcpt) = to.orcpt {
                    params.insert("ORCPT".into(), Some(orcpt));
                }
                self.rcpt_to.push(Address {
                    email: to.address,
                    parameters: (!params.is_empty()).then_some(params),
                });
                self.reply("250 2.1.5 OK");
            }
            Lookup::UnknownUser => {
                self.refused_rcpts += 1;
                self.error("550 5.1.1 Mailbox does not exist");
            }
            Lookup::NotServed => {
                self.refused_rcpts += 1;
                self.error("550 5.7.1 Relay not allowed");
            }
            Lookup::BadAddress => self.error("501 5.1.3 Bad recipient address"),
        }
    }

    async fn data(&mut self) -> Next {
        if self.mail_from.is_none() {
            self.error("503 5.5.1 MAIL first");
            return Next::Continue;
        }
        if self.rcpt_to.is_empty() {
            self.error("554 5.5.1 No valid recipients");
            return Next::Continue;
        }
        let Some(sealing_key) = self.settings.sealing_key else {
            self.reply("451 4.3.0 Not ready, try again later");
            return Next::Continue;
        };
        match crate::spool::Spool::begin(&self.app.paths.spool_in(), &sealing_key).await {
            Ok(incoming) => {
                self.reply("354 Start mail input; end with <CRLF>.<CRLF>");
                Next::Data(Box::new(incoming))
            }
            Err(e) => {
                self.app
                    .set_error(format!("could not write to the spool: {e}"));
                self.reply("451 4.3.0 Temporary failure, try again later");
                Next::Continue
            }
        }
    }

    fn record_end(&self) {
        self.app.record(
            "smtp.session",
            data([
                ("remoteIp", json!(self.peer.ip().to_string())),
                ("tls", json!(self.tls.is_some())),
                ("accepted", json!(self.accepted)),
                ("refusedRecipients", json!(self.refused_rcpts)),
            ]),
        );
    }
}
