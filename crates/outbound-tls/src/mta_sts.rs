/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

//! MTA-STS (RFC 8461) policies: parsing the fetched file, and matching MX
//! hosts against it. Fetching and caching stay with each caller.

use crate::{Mode, MxPattern, Policy};

/// A domain as an A-label, lowercased, for matching MX hosts.
fn to_a_label(domain: &str) -> String {
    if domain.is_ascii() {
        domain.to_ascii_lowercase()
    } else {
        idna::domain_to_ascii(domain)
            .map(|domain| domain.to_lowercase())
            .unwrap_or_else(|_| domain.to_lowercase())
    }
}

impl Policy {
    /// Parses a policy file (RFC 8461 §3.2), as fetched; `id` is the
    /// policy id from the TXT record.
    pub fn parse(mut data: &str, id: String) -> Result<Policy, String> {
        let mut mode = Mode::None;
        let mut max_age: u64 = 86400;
        let mut mx = Vec::new();

        while !data.is_empty() {
            if let Some((key, next_data)) = data.split_once(':') {
                let value = if let Some((value, next_data)) = next_data.split_once('\n') {
                    data = next_data;
                    value.trim()
                } else {
                    data = "";
                    next_data.trim()
                };
                match key.trim() {
                    "mx" => {
                        if let Some(suffix) = value.strip_prefix("*.") {
                            if !suffix.is_empty() {
                                mx.push(MxPattern::StartsWith(to_a_label(suffix)));
                            }
                        } else if !value.is_empty() {
                            mx.push(MxPattern::Equals(to_a_label(value)));
                        }
                    }
                    "max_age" => {
                        if let Ok(value) = value.parse() {
                            max_age = value;
                        }
                    }
                    "mode" => {
                        mode = match value {
                            "enforce" => Mode::Enforce,
                            "testing" => Mode::Testing,
                            "none" => Mode::None,
                            _ => return Err(format!("Unsupported mode {value:?}.")),
                        };
                    }
                    "version" if !value.eq_ignore_ascii_case("STSv1") => {
                        return Err(format!("Unsupported version {value:?}."));
                    }
                    _ => {}
                }
            } else {
                break;
            }
        }

        if !mx.is_empty() {
            Ok(Policy {
                id,
                mode,
                mx: mx.into_boxed_slice(),
                max_age,
            })
        } else {
            Err("No 'mx' entries found.".to_string())
        }
    }
}

impl Policy {
    /// Whether `mx_host` may be delivered to under this policy.
    pub fn verify(&self, mx_host: &str) -> bool {
        if self.mode != Mode::None {
            for mx_pattern in &self.mx {
                match mx_pattern {
                    MxPattern::Equals(host) => {
                        if host == mx_host {
                            return true;
                        }
                    }
                    MxPattern::StartsWith(domain) => {
                        if let Some((_, suffix)) = mx_host.split_once('.')
                            && suffix == domain
                        {
                            return true;
                        }
                    }
                }
            }

            false
        } else {
            true
        }
    }

    pub fn enforce(&self) -> bool {
        self.mode == Mode::Enforce
    }
}

#[cfg(test)]
mod test {
    use crate::Policy;

    #[test]
    fn mx_patterns_are_a_labels() {
        let policy = Policy::parse(
            concat!(
                "version: STSv1\n",
                "mode: enforce\n",
                "mx: *.\u{5de}\u{5d9}\u{5d9}\u{5dc}.\u{5e7}\u{5d5}\u{5dd}\n",
                "mx: MAIL.\u{5de}\u{5d9}\u{5d9}\u{5dc}.\u{5e7}\u{5d5}\u{5dd}\n",
                "max_age: 604800\n"
            ),
            "test".to_string(),
        )
        .unwrap();

        assert!(policy.verify("mx.xn--eebajf.xn--9dbq2a"));
        assert!(policy.verify("mail.xn--eebajf.xn--9dbq2a"));
        assert!(!policy.verify("mx.example.org"));
        assert!(policy.enforce());
    }
}
