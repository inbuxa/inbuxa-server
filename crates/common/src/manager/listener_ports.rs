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

#[cfg(test)]
mod tests {
    use super::*;

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
