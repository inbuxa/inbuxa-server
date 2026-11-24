/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use self::limiter::{ConcurrencyLimiter, InFlight};
use crate::{
    Server,
    config::server::ServerProtocol,
    expr::{functions::ResolveVariable, *},
};
use compact_str::ToCompactString;
use registry::{schema::enums::ExpressionVariable, types::ipmask::IpAddrOrMask};
use rustls::ServerConfig;
use std::fmt::Debug;
use std::{
    borrow::Cow,
    io,
    net::{IpAddr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
    time::timeout,
};
use tokio_rustls::{Accept, TlsAcceptor};
use trc::{Event, EventType, Key};
use utils::snowflake::SnowflakeIdGenerator;

pub mod acme;
pub mod asn;
pub mod autoconfig;
pub mod bind_health; // inbuxa: #485, listeners that can't open
pub mod control;
pub mod dkim;
pub mod dns;
pub mod legacy;
pub mod limiter;
pub mod listen;
pub mod mta;
pub mod public_only;
pub mod security;
pub mod stream;
pub mod tls;
pub mod webpush;
pub mod write_stall; // inbuxa: writes to a client that stopped reading time out

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub enum RcptResolution {
    Accept,
    Expand(Arc<[Box<str>]>),
    Rewrite(String),
    #[default]
    UnknownRecipient,
    UnknownDomain,
}

pub struct ServerInstance {
    pub id: String,
    pub protocol: ServerProtocol,
    pub acceptor: TcpAcceptor,
    pub limiter: ConcurrencyLimiter,
    pub proxy_networks: Vec<IpAddrOrMask>,
    pub tls_timeout: Duration,
    pub shutdown_rx: watch::Receiver<bool>,
    pub span_id_gen: Arc<SnowflakeIdGenerator>,
}

#[derive(Default)]
pub enum TcpAcceptor {
    Tls {
        config: Arc<ServerConfig>,
        acceptor: TlsAcceptor,
        implicit: bool,
    },
    #[default]
    Plain,
}

#[allow(clippy::large_enum_variant)]
pub enum TcpAcceptorResult<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    Tls(Accept<IO>),
    Plain(IO),
    Close,
}

pub struct SessionData<T: SessionStream> {
    pub stream: T,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub protocol: ServerProtocol,
    pub session_id: u64,
    pub in_flight: InFlight,
    pub instance: Arc<ServerInstance>,
}

pub trait SessionStream: AsyncRead + AsyncWrite + Unpin + 'static + Sync + Send {
    fn is_tls(&self) -> bool;
    fn tls_version_and_cipher(&self) -> (Cow<'static, str>, Cow<'static, str>);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionResult {
    Continue,
    Close,
    UpgradeTls,
}

pub trait SessionManager: Sync + Send + 'static + Clone {
    fn spawn<T: SessionStream>(
        &self,
        mut session: SessionData<T>,
        is_tls: bool,
        acme_core: Option<Server>,
        span_start: EventType,
        span_end: EventType,
    ) {
        let manager = self.clone();

        tokio::spawn(async move {
            let start_time = Instant::now();
            let local_port = session.local_port;
            let session_id;

            if is_tls {
                let tls_timeout = session.instance.tls_timeout;
                match timeout(
                    tls_timeout,
                    session
                        .instance
                        .acceptor
                        .accept(session.stream, acme_core, &session.instance),
                )
                .await
                {
                    Ok(TcpAcceptorResult::Tls(accept)) => {
                        match timeout(tls_timeout.saturating_sub(start_time.elapsed()), accept)
                            .await
                            .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::TimedOut)))
                        {
                            Ok(stream) => {
                                // Generate sessionId
                                session.session_id = session.instance.span_id_gen.generate();
                                session_id = session.session_id;

                                // Send span
                                Event::with_keys(
                                    span_start,
                                    vec![
                                        (Key::ListenerId, session.instance.id.clone().into()),
                                        (Key::LocalPort, session.local_port.into()),
                                        (Key::RemoteIp, session.remote_ip.into()),
                                        (Key::RemotePort, session.remote_port.into()),
                                        (Key::SpanId, session.session_id.into()),
                                    ],
                                )
                                .send_with_metrics();

                                manager
                                    .handle(SessionData {
                                        stream,
                                        local_ip: session.local_ip,
                                        local_port: session.local_port,
                                        remote_ip: session.remote_ip,
                                        remote_port: session.remote_port,
                                        protocol: session.protocol,
                                        session_id: session.session_id,
                                        in_flight: session.in_flight,
                                        instance: session.instance,
                                    })
                                    .await;
                            }
                            Err(err) => {
                                trc::event!(
                                    Tls(trc::TlsEvent::HandshakeError),
                                    ListenerId = session.instance.id.clone(),
                                    LocalPort = local_port,
                                    RemoteIp = session.remote_ip,
                                    RemotePort = session.remote_port,
                                    Reason = err.to_string(),
                                );

                                return;
                            }
                        }
                    }
                    Ok(TcpAcceptorResult::Plain(stream)) => {
                        // Generate sessionId
                        session.session_id = session.instance.span_id_gen.generate();
                        session_id = session.session_id;

                        // Send span
                        Event::with_keys(
                            span_start,
                            vec![
                                (Key::ListenerId, session.instance.id.clone().into()),
                                (Key::LocalPort, session.local_port.into()),
                                (Key::RemoteIp, session.remote_ip.into()),
                                (Key::RemotePort, session.remote_port.into()),
                                (Key::SpanId, session.session_id.into()),
                            ],
                        )
                        .send_with_metrics();

                        session.stream = stream;
                        manager.handle(session).await;
                    }
                    Ok(TcpAcceptorResult::Close) => return,
                    Err(_) => {
                        trc::event!(
                            Tls(trc::TlsEvent::HandshakeError),
                            ListenerId = session.instance.id.clone(),
                            LocalPort = local_port,
                            RemoteIp = session.remote_ip,
                            RemotePort = session.remote_port,
                            Reason = io::Error::from(io::ErrorKind::TimedOut).to_string(),
                        );

                        return;
                    }
                }
            } else {
                // Generate sessionId
                session.session_id = session.instance.span_id_gen.generate();
                session_id = session.session_id;

                // Send span
                Event::with_keys(
                    span_start,
                    vec![
                        (Key::ListenerId, session.instance.id.clone().into()),
                        (Key::LocalPort, session.local_port.into()),
                        (Key::RemoteIp, session.remote_ip.into()),
                        (Key::RemotePort, session.remote_port.into()),
                        (Key::SpanId, session.session_id.into()),
                    ],
                )
                .send_with_metrics();

                manager.handle(session).await;
            }

            // End span
            Event::with_keys(
                span_end,
                vec![
                    (Key::SpanId, session_id.into()),
                    (Key::Elapsed, start_time.elapsed().into()),
                ],
            )
            .send_with_metrics();
        });
    }

    fn handle<T: SessionStream>(
        self,
        session: SessionData<T>,
    ) -> impl std::future::Future<Output = ()> + Send;

    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send;
}

impl<T: SessionStream> ResolveVariable for SessionData<T> {
    fn resolve_variable(&self, variable: ExpressionVariable) -> crate::expr::Variable<'_> {
        match variable {
            ExpressionVariable::RemoteIp => self.remote_ip.to_compact_string().into(),
            ExpressionVariable::RemotePort => self.remote_port.into(),
            ExpressionVariable::LocalIp => self.local_ip.to_compact_string().into(),
            ExpressionVariable::LocalPort => self.local_port.into(),
            ExpressionVariable::Listener => self.instance.id.as_str().into(),
            ExpressionVariable::Protocol => self.protocol.as_str().into(),
            ExpressionVariable::IsTls => self.stream.is_tls().into(),
            _ => crate::expr::Variable::default(),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

impl Debug for TcpAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls {
                config, implicit, ..
            } => f
                .debug_struct("Tls")
                .field("config", config)
                .field("implicit", implicit)
                .finish(),
            Self::Plain => write!(f, "Plain"),
        }
    }
}

// inbuxa: moved to utils so crates below common can use it
pub use utils::public_ip::is_global_ip;

/// inbuxa: the mask of an IPv6 /64, the block one host is given and can use
/// any address of
pub const IPV6_PREFIX_MASK: u128 = u128::MAX << 64;

/// inbuxa: what failures and rate limits are counted by: the IPv4 address,
/// or the /64 of an IPv6 one. An IPv4-mapped address is its IPv4 address.
/// The relay groups its limits the same way.
pub fn ip_rate_key(ip: &IpAddr) -> Vec<u8> {
    match ip.to_canonical() {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets()[..8].to_vec(),
    }
}

/// inbuxa: what a ban for failures counted by `ip_rate_key` covers: the
/// IPv4 address, or the /64 of an IPv6 one
pub fn ip_ban_scope(ip: IpAddr) -> IpAddrOrMask {
    match ip.to_canonical() {
        IpAddr::V6(ip) => IpAddrOrMask::V6 {
            addr: Ipv6Addr::from(u128::from(ip) & IPV6_PREFIX_MASK),
            mask: IPV6_PREFIX_MASK,
        },
        ip => IpAddrOrMask::from_ip(ip),
    }
}

pub fn ip_to_bytes_prefix(prefix: u8, ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => {
            let mut buf = Vec::with_capacity(5);
            buf.push(prefix);
            buf.extend_from_slice(&ip.octets());
            buf
        }
        IpAddr::V6(ip) => {
            let mut buf = Vec::with_capacity(17);
            buf.push(prefix);
            buf.extend_from_slice(&ip.octets());
            buf
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_global_ip;
    use std::net::IpAddr;

    #[test]
    fn global_ip_classification() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "198.20.0.1",
            "192.0.3.1",
            "2606:4700::1111",
            "2a00:1450:4001::200e",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:0808:0808::",
            "2001:db9::1",
        ] {
            assert!(
                is_global_ip(&ip.parse::<IpAddr>().unwrap()),
                "expected {ip} to be global"
            );
        }

        for ip in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "198.18.0.1",
            "198.19.255.255",
            "192.0.0.1",
            "192.0.2.5",
            "192.88.99.1",
            "240.0.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "0.0.0.0",
            "0.1.2.3",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "2001:db8::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b::a00:1",
            "64:ff9b:1::7f00:1",
            "2002:7f00:1::",
            "2002:c0a8:101::",
            "100::1",
            "2001::1",
            "2001:20::1",
        ] {
            assert!(
                !is_global_ip(&ip.parse::<IpAddr>().unwrap()),
                "expected {ip} to be rejected"
            );
        }
    }
}
