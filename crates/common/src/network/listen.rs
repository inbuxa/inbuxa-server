/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{
    ServerInstance, SessionData, SessionManager, SessionStream, TcpAcceptor,
    limiter::{ConcurrencyLimiter, LimiterResult},
};
use crate::{
    BuildServer, Inner, Server,
    config::server::{Listener, Listeners, ServerProtocol, TcpListener},
};
use proxy_header::io::ProxiedStream;
use rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use store::registry::bootstrap::Bootstrap;
use tokio::{net::TcpStream, sync::watch, time::timeout};
use tokio_rustls::server::TlsStream;
use trc::{EventType, HttpEvent, ImapEvent, ManageSieveEvent, Pop3Event, SmtpEvent};
use utils::UnwrapFailure;

use super::control::ListenerControl;

impl Listener {
    pub fn spawn(
        self,
        manager: impl SessionManager,
        inner: Arc<Inner>,
        acceptor: TcpAcceptor,
        shutdown_rx: watch::Receiver<bool>,
    ) {
        // Prepare instance
        let instance = Arc::new(ServerInstance {
            id: self.id,
            protocol: self.protocol,
            proxy_networks: self.proxy_networks,
            limiter: ConcurrencyLimiter::new(self.max_connections),
            tls_timeout: self.tls_timeout,
            acceptor,
            shutdown_rx,
            span_id_gen: self.span_id_gen,
        });
        let is_tls = matches!(instance.acceptor, TcpAcceptor::Tls { implicit, .. } if implicit);
        let is_https = is_tls && self.protocol == ServerProtocol::Http;
        let has_proxies = !instance.proxy_networks.is_empty();

        // Spawn listeners
        for listener in self.listeners {
            let local_addr = listener.addr;

            // Obtain TCP options
            let opts = SocketOpts {
                nodelay: listener.nodelay,
                ttl: listener.ttl,
            };

            // inbuxa: #485: a listener opens in its own task, so a port still
            // held by the previous process can be waited out without holding
            // up the rest. Only listeners configured at startup may end the
            // process, and only when INBUXA_LISTENER_FAILURE=exit.
            let at_startup = super::bind_health::is_startup();

            // Spawn listener
            let mut shutdown_rx = instance.shutdown_rx.clone();
            let manager = manager.clone();
            let instance = instance.clone();
            let inner = inner.clone();
            tokio::spawn(async move {
                let key = format!("{} {}", instance.id, local_addr);
                let listener = match open(listener, &inner, &key).await {
                    Ok(listener) => {
                        trc::event!(
                            Network(trc::NetworkEvent::ListenStart),
                            ListenerId = instance.id.clone(),
                            LocalIp = local_addr.ip(),
                            LocalPort = local_addr.port(),
                            Tls = is_tls,
                        );

                        if inner.data.listener_control.failures().clear(&key) {
                            inner.build_server().publish_listener_failures().await;
                        }
                        listener
                    }
                    Err(err) => {
                        trc::event!(
                            Network(trc::NetworkEvent::ListenError),
                            ListenerId = instance.id.clone(),
                            LocalIp = local_addr.ip(),
                            LocalPort = local_addr.port(),
                            Tls = is_tls,
                            Reason = err.clone(),
                        );

                        if inner.data.listener_control.failures().set(&key, &err) {
                            inner.build_server().publish_listener_failures().await;
                        }
                        if at_startup
                            && super::bind_health::FailureMode::from_env()
                                == super::bind_health::FailureMode::Exit
                        {
                            trc::event!(
                                Server(trc::ServerEvent::StartupError),
                                Details = "A listener couldn't open and INBUXA_LISTENER_FAILURE=exit: stopping",
                                ListenerId = instance.id.clone(),
                                Reason = err.clone(),
                            );
                            eprintln!(
                                "Listener {key} couldn't open ({err}) and INBUXA_LISTENER_FAILURE=exit: stopping."
                            );
                            // Give the log a moment to write the events above
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            std::process::exit(1);
                        }
                        return;
                    }
                };

                let (span_start, span_end) = match self.protocol {
                    ServerProtocol::Smtp | ServerProtocol::Lmtp => (
                        EventType::Smtp(SmtpEvent::ConnectionStart),
                        EventType::Smtp(SmtpEvent::ConnectionEnd),
                    ),
                    ServerProtocol::Imap => (
                        EventType::Imap(ImapEvent::ConnectionStart),
                        EventType::Imap(ImapEvent::ConnectionEnd),
                    ),
                    ServerProtocol::Pop3 => (
                        EventType::Pop3(Pop3Event::ConnectionStart),
                        EventType::Pop3(Pop3Event::ConnectionEnd),
                    ),
                    ServerProtocol::Http => (
                        EventType::Http(HttpEvent::ConnectionStart),
                        EventType::Http(HttpEvent::ConnectionEnd),
                    ),
                    ServerProtocol::ManageSieve => (
                        EventType::ManageSieve(ManageSieveEvent::ConnectionStart),
                        EventType::ManageSieve(ManageSieveEvent::ConnectionEnd),
                    ),
                };

                const ACCEPT_BACKOFF: Duration = Duration::from_millis(5);
                const MAX_ACCEPT_BACKOFF: Duration = Duration::from_secs(1);
                let mut accept_backoff = ACCEPT_BACKOFF;

                loop {
                    tokio::select! {
                        stream = listener.accept() => {
                            match stream {
                                Ok((stream, remote_addr)) => {
                                    accept_backoff = ACCEPT_BACKOFF;

                                    let server = inner.build_server();
                                    let enable_acme = (is_https && server.has_acme_tls_providers()).then(|| server.clone());

                                    if has_proxies && instance.proxy_networks.iter().any(|network| network.matches(&remote_addr.ip())) {
                                        let instance = instance.clone();
                                        let manager = manager.clone();

                                        // Set socket options
                                        opts.apply(&stream);

                                        tokio::spawn(async move {
                                            match ProxiedStream::create_from_tokio(stream, Default::default()).await {
                                                Ok(stream) =>{
                                                    let (remote_addr, local_addr) = stream.proxy_header()
                                                                            .proxied_address()
                                                                            .map(|addr| {
                                                                                let local_addr = match addr.destination.ip() {
                                                                                    IpAddr::V6(ip) => ip
                                                                                        .to_ipv4_mapped()
                                                                                        .map(|ip| SocketAddr::new(IpAddr::V4(ip), addr.destination.port()))
                                                                                        .unwrap_or(addr.destination),
                                                                                    _ => addr.destination,
                                                                                };

                                                                                (addr.source, local_addr)
                                                                            })
                                                                            .unwrap_or((remote_addr, local_addr));
                                                    if let Some(session) = instance.build_session(stream, local_addr, remote_addr, &server) {
                                                        // Spawn session
                                                        manager.spawn(session, is_tls, enable_acme, span_start, span_end);
                                                    }
                                                }
                                                Err(err) => {
                                                    trc::event!(
                                                        Network(trc::NetworkEvent::ProxyError),
                                                        ListenerId = instance.id.clone(),
                                                        LocalIp = local_addr.ip(),
                                                        LocalPort = local_addr.port(),
                                                        Tls = is_tls,
                                                        Reason = err.to_string(),
                                                    );
                                                }
                                            }
                                        });
                                    } else if let Some(session) = instance.build_session(stream, local_addr, remote_addr, &server) {
                                        // Set socket options
                                        opts.apply(&session.stream);

                                        // Spawn session
                                        manager.spawn(session, is_tls, enable_acme, span_start, span_end);
                                    }
                                }
                                Err(err) => {
                                    if matches!(
                                        err.kind(),
                                        std::io::ErrorKind::ConnectionAborted
                                            | std::io::ErrorKind::ConnectionReset
                                            | std::io::ErrorKind::Interrupted
                                    ) {
                                        continue;
                                    }

                                    trc::event!(
                                        Network(trc::NetworkEvent::AcceptError),
                                        ListenerId = instance.id.clone(),
                                        LocalIp = local_addr.ip(),
                                        LocalPort = local_addr.port(),
                                        Tls = is_tls,
                                        Reason = err.to_string(),
                                    );

                                    tokio::select! {
                                        _ = tokio::time::sleep(accept_backoff) => {}
                                        _ = shutdown_rx.changed() => {
                                            manager.shutdown().await;
                                            break;
                                        }
                                    }

                                    accept_backoff = (accept_backoff * 2).min(MAX_ACCEPT_BACKOFF);
                                }
                            }
                        },
                        _ = shutdown_rx.changed() => {

                            trc::event!(
                                Network(trc::NetworkEvent::ListenStop),
                                ListenerId = instance.id.clone(),
                                LocalIp = local_addr.ip(),
                                Tls = is_tls,
                                LocalPort = local_addr.port(),
                            );

                            manager.shutdown().await;
                            break;
                        }
                    };
                }
            });
        }
    }
}

trait BuildSession {
    fn build_session<T: SessionStream>(
        &self,
        stream: T,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        server: &Server,
    ) -> Option<SessionData<T>>;
}

impl BuildSession for Arc<ServerInstance> {
    fn build_session<T: SessionStream>(
        &self,
        stream: T,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        server: &Server,
    ) -> Option<SessionData<T>> {
        // Convert mapped IPv6 addresses to IPv4
        let remote_ip = match remote_addr.ip() {
            IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(ip)),
            remote_ip => remote_ip,
        };
        let remote_port = remote_addr.port();

        // Check if blocked
        if server.is_ip_blocked(remote_ip) {
            trc::event!(
                Security(trc::SecurityEvent::IpBlocked),
                ListenerId = self.id.clone(),
                LocalPort = local_addr.port(),
                RemoteIp = remote_ip,
                RemotePort = remote_port,
            );
            None
        } else if let LimiterResult::Allowed(in_flight) = self.limiter.is_allowed() {
            // Enforce concurrency
            SessionData {
                stream,
                in_flight,
                local_ip: local_addr.ip(),
                local_port: local_addr.port(),
                session_id: 0,
                remote_ip,
                remote_port,
                protocol: self.protocol,
                instance: self.clone(),
            }
            .into()
        } else {
            trc::event!(
                Limit(trc::LimitEvent::ConcurrentConnection),
                ListenerId = self.id.clone(),
                LocalPort = local_addr.port(),
                RemoteIp = remote_ip,
                RemotePort = remote_port,
                Limit = self.limiter.max_concurrent(),
            );

            None
        }
    }
}

pub struct SocketOpts {
    pub nodelay: bool,
    pub ttl: Option<u32>,
}

impl SocketOpts {
    pub fn apply(&self, stream: &TcpStream) {
        // Set TCP options
        if let Err(err) = stream.set_nodelay(self.nodelay) {
            trc::event!(
                Network(trc::NetworkEvent::SetOptError),
                Reason = err.to_string(),
                Details = "Failed to set TCP_NODELAY",
            );
        }
        if let Some(ttl) = self.ttl
            && let Err(err) = stream.set_ttl(ttl)
        {
            trc::event!(
                Network(trc::NetworkEvent::SetOptError),
                Reason = err.to_string(),
                Details = "Failed to set TTL",
            );
        }
    }
}

impl Listeners {
    /// Binds every socket, reporting each failure against its listener.
    ///
    /// Split out of [`Listeners::bind_and_drop_priv`] so a listener can be
    /// bound again at runtime, when the legacy-protocols switch puts one back
    /// (LP-5), without dropping privileges a second time. A port below 1024
    /// will fail here once privileges are gone, which is one of the cases
    /// LP-5 expects and reports rather than hides.
    pub fn bind(&self, bp: &mut Bootstrap) {
        for server in &self.servers {
            for listener in &server.listeners {
                if let Err(err) = listener.socket.bind(listener.addr) {
                    // inbuxa: K-S1: the image no longer carries the capability
                    // to bind low ports, so say what grants it
                    let hint = if err.kind() == std::io::ErrorKind::PermissionDenied
                        && listener.addr.port() < 1024
                    {
                        " (ports below 1024 need CAP_NET_BIND_SERVICE, or the sysctl \
                         net.ipv4.ip_unprivileged_port_start=0; or move the listener to \
                         a higher port)"
                    } else {
                        ""
                    };
                    bp.build_error(
                        server.registry_id,
                        format!("Failed to bind to {}: {}{hint}", listener.addr, err),
                    );
                }
            }
        }
    }

    pub fn bind_and_drop_priv(&self, bp: &mut Bootstrap) {
        // Bind as root
        self.bind(bp);

        // Drop privileges
        #[cfg(not(target_env = "msvc"))]
        {
            if let Ok(run_as_user) = std::env::var("RUN_AS_USER") {
                let mut pd = privdrop::PrivDrop::default()
                    .user(run_as_user)
                    .fallback_to_ids_if_names_are_numeric();
                if let Ok(run_as_group) = std::env::var("RUN_AS_GROUP") {
                    pd = pd
                        .group(run_as_group)
                        .fallback_to_ids_if_names_are_numeric();
                }
                pd.apply().failed("Failed to drop privileges");
            }
        }
    }

    pub fn spawn(
        mut self,
        spawn: impl Fn(Listener, TcpAcceptor, watch::Receiver<bool>),
    ) -> (watch::Sender<bool>, watch::Receiver<bool>) {
        // Spawn listeners
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        for server in self.servers {
            let acceptor = self
                .tcp_acceptors
                .remove(&server.id)
                .unwrap_or(TcpAcceptor::Plain);

            spawn(server, acceptor, shutdown_rx.clone());
        }
        (shutdown_tx, shutdown_rx)
    }

    /// As [`Listeners::spawn`], but each listener gets its own shutdown
    /// channel, registered in `control` under the listener's id, so one can be
    /// stopped without touching the others (legacy-protocols LP-2).
    ///
    /// The returned sender no longer reaches the listeners: whole-server
    /// shutdown must also call [`ListenerControl::stop_all`]. `control` has to
    /// outlive the listeners, because it owns the sending ends — dropping it
    /// would stop every listener at once.
    pub fn spawn_with_control(
        mut self,
        control: &ListenerControl,
        spawn: impl Fn(Listener, TcpAcceptor, watch::Receiver<bool>),
    ) -> (watch::Sender<bool>, watch::Receiver<bool>) {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        for server in self.servers {
            let acceptor = self
                .tcp_acceptors
                .remove(&server.id)
                .unwrap_or(TcpAcceptor::Plain);

            let ports = server
                .listeners
                .iter()
                .map(|listener| listener.addr.port())
                .collect();
            let listener_rx = control.register(server.id.clone(), server.protocol, ports);

            spawn(server, acceptor, listener_rx);
        }
        (shutdown_tx, shutdown_rx)
    }
}

/// inbuxa: #485: listens on a socket, binding it again if the bind at
/// startup failed. A port in use is retried for `RETRY_FOR`, and recorded
/// as a failure meanwhile, so the node reports not ready while it waits.
async fn open(
    listener: TcpListener,
    inner: &Arc<Inner>,
    key: &str,
) -> Result<tokio::net::TcpListener, String> {
    let inner_ = inner.clone();
    let key_ = key.to_string();
    open_retrying(listener, super::bind_health::RETRY_FOR, move |retrying| {
        if inner_
            .data
            .listener_control
            .failures()
            .set(&key_, &retrying)
        {
            let inner = inner_.clone();
            tokio::spawn(async move {
                inner.build_server().publish_listener_failures().await;
            });
        }
    })
    .await
}

/// Binds (if the bind at startup failed) and listens. A port in use is
/// retried with backoff for `retry_for`, calling `on_retry` once with the
/// reason when the waiting starts; any other bind error fails at once.
async fn open_retrying(
    listener: TcpListener,
    retry_for: Duration,
    mut on_retry: impl FnMut(String),
) -> Result<tokio::net::TcpListener, String> {
    use super::bind_health::{is_retryable, next_backoff};

    let started = std::time::Instant::now();
    let mut backoff = None;
    while !listener.is_bound() {
        let Err(err) = listener.socket.bind(listener.addr) else {
            break;
        };
        let reason = format!("Failed to bind to {}: {}", listener.addr, err);
        if !is_retryable(&err) {
            return Err(reason);
        }
        let Some(wait) = next_backoff(started, retry_for, backoff) else {
            return Err(format!(
                "{reason} (still in use after {} s)",
                retry_for.as_secs()
            ));
        };
        if backoff.is_none() {
            on_retry(format!("{reason}; retrying"));
        }
        backoff = Some(wait);
        tokio::time::sleep(wait).await;
    }
    listener.listen()
}

impl TcpListener {
    fn is_bound(&self) -> bool {
        self.socket
            .local_addr()
            .is_ok_and(|bound| bound.port() != 0)
    }

    pub fn listen(self) -> Result<tokio::net::TcpListener, String> {
        // inbuxa: a socket whose bind failed is still unbound, and listen()
        // on it makes the kernel pick a random port on every interface
        if !self
            .socket
            .local_addr()
            .is_ok_and(|bound| bound.port() != 0)
        {
            return Err(format!("Not listening on {}: it isn't bound", self.addr));
        }
        self.socket
            .listen(self.backlog.unwrap_or(1024))
            .map_err(|err| format!("Failed to listen on {}: {}", self.addr, err))
    }
}

impl ServerInstance {
    pub async fn tls_accept<T: SessionStream>(
        &self,
        stream: T,
        session_id: u64,
    ) -> Result<TlsStream<T>, ()> {
        match &self.acceptor {
            TcpAcceptor::Tls { acceptor, .. } => {
                match timeout(self.tls_timeout, acceptor.accept(stream))
                    .await
                    .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::TimedOut)))
                {
                    Ok(stream) => {
                        trc::event!(
                            Tls(trc::TlsEvent::Handshake),
                            ListenerId = self.id.clone(),
                            SpanId = session_id,
                            Version = format!(
                                "{:?}",
                                stream
                                    .get_ref()
                                    .1
                                    .protocol_version()
                                    .unwrap_or(rustls::ProtocolVersion::TLSv1_3)
                            ),
                            Details = format!(
                                "{:?}",
                                stream
                                    .get_ref()
                                    .1
                                    .negotiated_cipher_suite()
                                    .unwrap_or(TLS13_AES_128_GCM_SHA256)
                            )
                        );
                        Ok(stream)
                    }
                    Err(err) => {
                        trc::event!(
                            Tls(trc::TlsEvent::HandshakeError),
                            ListenerId = self.id.clone(),
                            SpanId = session_id,
                            Reason = err.to_string(),
                        );
                        Err(())
                    }
                }
            }
            TcpAcceptor::Plain => {
                trc::event!(
                    Tls(trc::TlsEvent::NotConfigured),
                    ListenerId = self.id.clone(),
                    SpanId = session_id,
                );
                Err(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::open_retrying;
    use crate::config::server::TcpListener;
    use std::time::Duration;
    use tokio::net::TcpSocket;

    fn listener(socket: TcpSocket, addr: &str) -> TcpListener {
        TcpListener {
            socket,
            addr: addr.parse().unwrap(),
            backlog: None,
            ttl: None,
            nodelay: true,
        }
    }

    #[tokio::test]
    async fn an_unbound_socket_is_not_listened_on() {
        // What a failed bind leaves behind: listening would pick a random port
        let socket = TcpSocket::new_v4().unwrap();
        let err = listener(socket, "0.0.0.0:25").listen().unwrap_err();
        assert!(err.contains("isn't bound"), "{err}");
    }

    // inbuxa: #485
    #[tokio::test]
    async fn a_port_in_use_is_waited_for() {
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = held.local_addr().unwrap().to_string();
        let socket = TcpSocket::new_v4().unwrap();
        let mut retried = Vec::new();
        let opening = tokio::spawn(async move {
            let result =
                open_retrying(listener(socket, &addr), Duration::from_secs(20), |reason| {
                    retried.push(reason)
                })
                .await;
            (result, retried)
        });
        tokio::time::sleep(Duration::from_millis(1500)).await;
        drop(held);
        let (result, retried) = opening.await.unwrap();
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(retried.len(), 1, "{retried:?}");
        assert!(retried[0].contains("retrying"), "{retried:?}");
    }

    #[tokio::test]
    async fn a_port_held_too_long_fails() {
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = held.local_addr().unwrap().to_string();
        let socket = TcpSocket::new_v4().unwrap();
        let started = std::time::Instant::now();
        let err = open_retrying(listener(socket, &addr), Duration::from_secs(2), |_| {})
            .await
            .unwrap_err();
        assert!(err.contains("still in use after 2 s"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(held);
    }

    #[tokio::test]
    async fn other_bind_errors_are_not_retried() {
        // An address this host doesn't have
        let socket = TcpSocket::new_v4().unwrap();
        let started = std::time::Instant::now();
        let mut retried = 0;
        let err = open_retrying(
            listener(socket, "192.0.2.1:2525"),
            Duration::from_secs(20),
            |_| retried += 1,
        )
        .await
        .unwrap_err();
        assert!(err.contains("Failed to bind"), "{err}");
        assert_eq!(retried, 0);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn a_bound_socket_listens_even_on_port_zero() {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let bound = listener(socket, "127.0.0.1:0").listen().unwrap();
        assert_ne!(bound.local_addr().unwrap().port(), 0);
    }
}
