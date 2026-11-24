/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: K-S1: the ports of the default listeners, from the environment.
//!
//! A new store gets one listener per protocol on its standard port (25, 465,
//! 993, ...). Ports below 1024 need a privilege that a Kubernetes pod with
//! every capability dropped doesn't have, so `INBUXA_LISTENER_PORTS` moves
//! them, or leaves some out:
//!
//! ```text
//! INBUXA_LISTENER_PORTS=smtp=2525,submissions=4465,imaps=9993,pop3s=off,https=8443
//! ```
//!
//! It is read only when those listeners are created, on a store that has no
//! listeners yet. After that the registry holds them and they are changed
//! there, like any other setting.

/// The listeners a new store gets: name, port and whether TLS is implicit.
/// The names are what `INBUXA_LISTENER_PORTS` uses.
pub const DEFAULT_LISTENERS: [(&str, u16, bool); 7] = [
    ("smtp", 25, false),
    ("submissions", 465, true),
    ("imaps", 993, true),
    ("pop3s", 995, true),
    ("sieve", 4190, false),
    ("https", 443, true),
    ("http", 8080, false),
];

pub const ENV_VAR: &str = "INBUXA_LISTENER_PORTS";

/// The default listeners after the environment's changes: name, port and
/// whether TLS is implicit, in [`DEFAULT_LISTENERS`] order. A listener
/// turned off is left out.
pub fn default_listeners(spec: Option<&str>) -> Result<Vec<(&'static str, u16, bool)>, String> {
    let mut listeners = DEFAULT_LISTENERS
        .iter()
        .map(|&(name, port, tls)| (name, Some(port), tls))
        .collect::<Vec<_>>();
    let mut seen = Vec::new();

    for item in spec
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let Some((name, port)) = item.split_once('=') else {
            return Err(format!(
                "{ENV_VAR}: '{item}' is not name=port (for example smtp=2525)"
            ));
        };
        let (name, port) = (name.trim(), port.trim());
        let Some(entry) = listeners.iter_mut().find(|entry| entry.0 == name) else {
            return Err(format!(
                "{ENV_VAR}: there is no default listener '{name}'; they are {}",
                DEFAULT_LISTENERS.map(|entry| entry.0).join(", ")
            ));
        };
        if seen.contains(&name) {
            return Err(format!("{ENV_VAR}: '{name}' is given twice"));
        }
        seen.push(entry.0);

        entry.1 = if port.eq_ignore_ascii_case("off") {
            None
        } else {
            match port.parse::<u16>() {
                Ok(port) if port > 0 => Some(port),
                _ => {
                    return Err(format!(
                        "{ENV_VAR}: '{port}' is not a port for '{name}' (1 to 65535, or off)"
                    ));
                }
            }
        };
    }

    let listeners = listeners
        .into_iter()
        .filter_map(|(name, port, tls)| port.map(|port| (name, port, tls)))
        .collect::<Vec<_>>();
    for (i, (name, port, _)) in listeners.iter().enumerate() {
        if let Some((other, _, _)) = listeners[..i].iter().find(|entry| entry.1 == *port) {
            return Err(format!(
                "{ENV_VAR}: '{other}' and '{name}' would both listen on port {port}"
            ));
        }
    }

    Ok(listeners)
}

/// inbuxa: K-C6: PROXY protocol copies of the mail listeners, from the
/// environment. Behind a load balancer that sends PROXY v2 (a cloud LB,
/// HAProxy), the server needs listeners that take the client's address from
/// the header, trusting it only from the load balancer:
///
/// ```text
/// INBUXA_MAIL_PROXY_LISTENERS=smtp=10025,submissions=10465,imaps=10993
/// INBUXA_MAIL_PROXY_TRUSTED_NETWORKS=10.0.0.10,10.0.0.11
/// ```
///
/// Each named listener in the store gets a copy on the port given, with the
/// same protocol and TLS, that trusts PROXY headers from those networks
/// only. The copies aren't stored; the listeners they copy keep serving as
/// they are, without PROXY. A network wider than /8 (IPv4) or /8 (IPv6) is
/// refused: trusting everyone lets anyone who reaches the port say who they
/// are.
pub const PROXY_ENV_VAR: &str = "INBUXA_MAIL_PROXY_LISTENERS";
pub const PROXY_NETWORKS_ENV_VAR: &str = "INBUXA_MAIL_PROXY_TRUSTED_NETWORKS";

/// The listeners `INBUXA_MAIL_PROXY_LISTENERS` may copy.
pub const MAIL_LISTENERS: [&str; 5] = ["smtp", "submissions", "imaps", "pop3s", "sieve"];

#[derive(Debug, PartialEq, Eq)]
pub struct ProxyListeners {
    /// Listener name and the port of its copy
    pub ports: Vec<(&'static str, u16)>,
    pub trusted: Vec<registry::types::ipmask::IpAddrOrMask>,
}

/// `None` when neither variable is set.
pub fn proxy_listeners(
    spec: Option<&str>,
    networks: Option<&str>,
) -> Result<Option<ProxyListeners>, String> {
    let spec = spec.map(str::trim).filter(|s| !s.is_empty());
    let networks = networks.map(str::trim).filter(|s| !s.is_empty());
    let (spec, networks) = match (spec, networks) {
        (None, None) => return Ok(None),
        (Some(_), None) => {
            return Err(format!(
                "{PROXY_ENV_VAR} is set without {PROXY_NETWORKS_ENV_VAR}: name the load \
                 balancer's addresses, the only ones whose PROXY headers are believed"
            ));
        }
        (None, Some(_)) => {
            return Err(format!(
                "{PROXY_NETWORKS_ENV_VAR} is set without {PROXY_ENV_VAR}, which names the \
                 listeners that take PROXY headers"
            ));
        }
        (Some(spec), Some(networks)) => (spec, networks),
    };

    let mut ports: Vec<(&'static str, u16)> = Vec::new();
    for item in spec.split(',').map(str::trim).filter(|i| !i.is_empty()) {
        let Some((name, port)) = item.split_once('=') else {
            return Err(format!(
                "{PROXY_ENV_VAR}: '{item}' is not name=port (for example smtp=10025)"
            ));
        };
        let (name, port) = (name.trim(), port.trim());
        let Some(name) = MAIL_LISTENERS.iter().copied().find(|n| *n == name) else {
            return Err(format!(
                "{PROXY_ENV_VAR}: '{name}' is not a mail listener; they are {}",
                MAIL_LISTENERS.join(", ")
            ));
        };
        let port = match port.parse::<u16>() {
            Ok(port) if port > 0 => port,
            _ => {
                return Err(format!(
                    "{PROXY_ENV_VAR}: '{port}' is not a port for '{name}' (1 to 65535)"
                ));
            }
        };
        if ports.iter().any(|(n, _)| *n == name) {
            return Err(format!("{PROXY_ENV_VAR}: '{name}' is given twice"));
        }
        if let Some((other, _)) = ports.iter().find(|(_, p)| *p == port) {
            return Err(format!(
                "{PROXY_ENV_VAR}: '{other}' and '{name}' would both listen on port {port}"
            ));
        }
        ports.push((name, port));
    }

    let mut trusted = Vec::new();
    for item in networks
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|i| !i.is_empty())
    {
        trusted.push(item.parse().map_err(|_| {
            format!(
                "{PROXY_NETWORKS_ENV_VAR}: '{item}' is not an address or a network of /8 or \
                 narrower"
            )
        })?);
    }
    if ports.is_empty() || trusted.is_empty() {
        return Err(format!(
            "{PROXY_ENV_VAR} and {PROXY_NETWORKS_ENV_VAR} name nothing"
        ));
    }
    Ok(Some(ProxyListeners { ports, trusted }))
}

/// inbuxa: #571: where the recovery-mode and bootstrap listener listens.
pub const RECOVERY_PORT_ENV_VAR: &str = "INBUXA_RECOVERY_MODE_PORT";
pub const DEFAULT_RECOVERY_PORT: u16 = 8080;

/// The recovery-mode listener's port, from [`RECOVERY_PORT_ENV_VAR`]; 8080
/// when it isn't set. A value that isn't a port is refused: falling back to
/// 8080 would move the listener without a word.
pub fn recovery_mode_port(value: Option<&str>) -> Result<u16, String> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(DEFAULT_RECOVERY_PORT),
        Some(value) => match value.parse::<u16>() {
            Ok(port) if port > 0 => Ok(port),
            _ => Err(format!(
                "{RECOVERY_PORT_ENV_VAR}: '{value}' is not a port (1 to 65535)"
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_mode_port_read() {
        assert_eq!(recovery_mode_port(None), Ok(8080));
        assert_eq!(recovery_mode_port(Some("")), Ok(8080));
        assert_eq!(recovery_mode_port(Some("8081")), Ok(8081));
        assert_eq!(recovery_mode_port(Some(" 9090 ")), Ok(9090));
        for value in ["808O", "0", "65536", "-1", "8080/tcp"] {
            let err = recovery_mode_port(Some(value)).unwrap_err();
            assert!(
                err.contains(RECOVERY_PORT_ENV_VAR) && err.contains(&format!("'{value}'")),
                "{value}: {err}"
            );
        }
    }

    #[test]
    fn proxy_listeners_read() {
        assert_eq!(proxy_listeners(None, None), Ok(None));
        assert_eq!(proxy_listeners(Some(" "), Some("")), Ok(None));
        let found = proxy_listeners(
            Some("smtp=10025, imaps=10993"),
            Some("10.0.0.10 192.168.0.0/16,fd00::/8"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(found.ports, vec![("smtp", 10025), ("imaps", 10993)]);
        assert_eq!(found.trusted.len(), 3);
    }

    #[test]
    fn proxy_listeners_refused() {
        for (spec, networks, said) in [
            (
                "smtp=10025",
                "",
                "without INBUXA_MAIL_PROXY_TRUSTED_NETWORKS",
            ),
            ("", "10.0.0.1", "without INBUXA_MAIL_PROXY_LISTENERS"),
            ("http=10080", "10.0.0.1", "not a mail listener"),
            ("smtp=0", "10.0.0.1", "not a port"),
            ("smtp=1,smtp=2", "10.0.0.1", "given twice"),
            ("smtp=1,imaps=1", "10.0.0.1", "would both listen"),
            ("smtp=10025", "0.0.0.0/0", "narrower"),
            ("smtp=10025", "::/0", "narrower"),
            ("smtp=10025", "not-an-address", "narrower"),
        ] {
            let err = proxy_listeners(Some(spec), Some(networks)).unwrap_err();
            assert!(err.contains(said), "{spec} {networks}: {err}");
        }
    }

    fn ports(spec: &str) -> Vec<(&'static str, u16)> {
        default_listeners(Some(spec))
            .unwrap()
            .into_iter()
            .map(|(name, port, _)| (name, port))
            .collect()
    }

    #[test]
    fn unset_is_the_standard_ports() {
        let standard = DEFAULT_LISTENERS
            .map(|(name, port, _)| (name, port))
            .to_vec();
        assert_eq!(
            default_listeners(None)
                .unwrap()
                .into_iter()
                .map(|(name, port, _)| (name, port))
                .collect::<Vec<_>>(),
            standard
        );
        assert_eq!(ports(""), standard);
        assert_eq!(ports(" , "), standard);
    }

    #[test]
    fn moves_and_turns_off() {
        assert_eq!(
            ports("smtp=2525, submissions = 4465,imaps=9993,pop3s=OFF,https=8443"),
            vec![
                ("smtp", 2525),
                ("submissions", 4465),
                ("imaps", 9993),
                ("sieve", 4190),
                ("https", 8443),
                ("http", 8080),
            ]
        );
        // TLS stays with the listener, not the position
        let listeners = default_listeners(Some("smtp=off")).unwrap();
        assert_eq!(listeners[0], ("submissions", 465, true));
    }

    #[test]
    fn refuses_what_it_cannot_mean() {
        for (spec, said) in [
            ("smtp", "not name=port"),
            ("imap=143", "no default listener 'imap'"),
            ("smtp=0", "not a port"),
            ("smtp=70000", "not a port"),
            ("smtp=twentyfive", "not a port"),
            ("smtp=2525,smtp=2526", "given twice"),
            (
                "https=8080",
                "'https' and 'http' would both listen on port 8080",
            ),
        ] {
            let err = default_listeners(Some(spec)).unwrap_err();
            assert!(err.contains(said), "{spec}: {err}");
        }
        // A port freed by turning a listener off can be taken
        assert!(default_listeners(Some("http=off,https=8080")).is_ok());
    }
}
