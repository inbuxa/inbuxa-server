/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! A domain's MX and SPF records when relays take its mail (relay spec,
//! RL-25). The relays named are those enabled and joined, with a public
//! name, that serve the domain: their settings' `domains` name it, or name
//! none. With none of them, a domain's records are made as without relays.
//!
//! What the records are made of is kept as a hash under `d`: when it
//! changes, a node queues the domains' DNS tasks again ([`dns_change`]).

use super::{FEATURE, Json, Relay};
use serde::Serialize as SerdeSerialize;
use store::{
    SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

const KIND_DNS: u8 = b'd';

/// SPF allows ten mechanisms that look up DNS (RFC 7208, 4.6.4).
pub const SPF_LOOKUPS_MAX: usize = 10;

/// The relays' part of one domain's records.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize)]
pub struct RelayDns {
    /// The MX set: each relay's public name and preference, lowest first.
    pub mx: Vec<(String, u16)>,
    /// The relays that send mail, not `inboundOnly` (RL-20).
    pub senders: Vec<String>,
    /// Whether this server still sends mail itself: no enabled relay has
    /// `sendThrough` on (RL-24).
    pub server_sends: bool,
}

/// A relay that can be in a domain's records: enabled, joined, and with a
/// public name.
fn counted(relay: &Relay) -> bool {
    relay.enabled && relay.join.relay_pin.is_some() && !relay.settings.hostname.trim().is_empty()
}

fn takes_mail_for(relay: &Relay, domain: &str) -> bool {
    counted(relay)
        && (relay.settings.domains.is_empty()
            || relay
                .settings
                .domains
                .iter()
                .any(|d| d.trim().eq_ignore_ascii_case(domain)))
}

fn host(relay: &Relay) -> String {
    relay
        .settings
        .hostname
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// The relays' records for `domain`, or `None` when no relay takes its mail.
pub fn for_domain(relays: &[Relay], domain: &str) -> Option<RelayDns> {
    let domain = domain.trim().trim_end_matches('.');
    let mut mx: Vec<(String, u16)> = Vec::new();
    let mut senders: Vec<String> = Vec::new();
    for relay in relays.iter().filter(|r| takes_mail_for(r, domain)) {
        let host = host(relay);
        match mx.iter_mut().find(|(h, _)| *h == host) {
            // One name on two relays: the lower preference
            Some((_, preference)) => *preference = (*preference).min(relay.mx_preference),
            None => mx.push((host.clone(), relay.mx_preference)),
        }
        if !relay.inbound_only && !senders.contains(&host) {
            senders.push(host);
        }
    }
    if mx.is_empty() {
        return None;
    }
    mx.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    senders.sort();
    Some(RelayDns {
        mx,
        senders,
        server_sends: !relays.iter().any(|r| r.enabled && r.send_through),
    })
}

/// The domain's SPF policy, given the hosts that send for it: each by its
/// address records, as `a:` (a relay's link address isn't the one it sends
/// from). `None` past [`SPF_LOOKUPS_MAX`], where every check would fail.
pub fn spf_policy(hosts: &[String]) -> Option<String> {
    if hosts.len() > SPF_LOOKUPS_MAX {
        return None;
    }
    let mut policy = String::from("v=spf1");
    for host in hosts {
        policy.push_str(" a:");
        policy.push_str(host);
    }
    policy.push_str(" -all");
    Some(policy)
}

/// Everything the relays put in any domain's MX and SPF records.
#[derive(SerdeSerialize)]
struct Inputs<'a> {
    relays: Vec<(u32, &'a str, u16, bool, &'a [String])>,
    server_sends: bool,
}

fn inputs_hash(relays: &[Relay]) -> u64 {
    let mut listed: Vec<_> = relays
        .iter()
        .filter(|r| counted(r))
        .map(|r| {
            (
                r.id,
                r.settings.hostname.trim(),
                r.mx_preference,
                r.inbound_only,
                r.settings.domains.as_slice(),
            )
        })
        .collect();
    listed.sort();
    if listed.is_empty() {
        // No relay in any record: the records are the server's own, and
        // `sendThrough` alone changes none of them
        return 0;
    }
    let inputs = Inputs {
        relays: listed,
        server_sends: !relays.iter().any(|r| r.enabled && r.send_through),
    };
    xxhash_rust::xxh3::xxh3_64(&serde_json::to_vec(&inputs).unwrap_or_default())
}

fn dns_class() -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key: vec![FEATURE, KIND_DNS],
    })
}

/// What the relays now put in the domains' DNS records, hashed, when it
/// isn't what was last recorded on any node. With nothing recorded yet, no
/// relays in any record is no change, so a server with none publishes
/// nothing new when it first runs this.
pub async fn dns_change(data: &Store, relays: &[Relay]) -> trc::Result<Option<u64>> {
    let hash = inputs_hash(relays);
    let recorded = data
        .get_value::<Json<u64>>(ValueKey::from(dns_class()))
        .await
        .caused_by(trc::location!())?
        .map_or(0, |Json(hash)| hash);
    Ok((recorded != hash).then_some(hash))
}

/// Records a [`dns_change`] once the domains' DNS tasks are queued.
pub async fn record_dns(data: &Store, hash: u64) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(dns_class(), Json(&hash).serialize()?);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(id: u32, host: &str, preference: u16) -> Relay {
        let mut relay: Relay = serde_json::from_value(serde_json::json!({
            "name": format!("r{id}"),
            "address": "10.8.0.2",
        }))
        .unwrap();
        relay.id = id;
        relay.settings.hostname = host.into();
        relay.mx_preference = preference;
        relay.join.relay_pin = Some([1; 32]);
        relay
    }

    #[test]
    fn relays_are_the_mx_set() {
        let mut inbound = relay(3, "mx3.example.com", 30);
        inbound.inbound_only = true;
        let mut waiting = relay(4, "mx4.example.com", 5);
        waiting.join.relay_pin = None;
        let mut off = relay(5, "mx5.example.com", 5);
        off.enabled = false;
        let mut other = relay(6, "mx6.example.com", 5);
        other.settings.domains = vec!["other.test".into()];
        let relays = [
            relay(1, "MX2.example.com.", 20),
            relay(2, "mx1.example.com", 10),
            inbound,
            waiting,
            off,
            other,
        ];
        let dns = for_domain(&relays, "example.com").unwrap();
        assert_eq!(
            dns.mx,
            [
                ("mx1.example.com".to_string(), 10),
                ("mx2.example.com".to_string(), 20),
                ("mx3.example.com".to_string(), 30),
            ]
        );
        // Not the one that only takes mail in
        assert_eq!(dns.senders, ["mx1.example.com", "mx2.example.com"]);
        assert!(dns.server_sends);

        // A relay for some domains only is theirs
        let dns = for_domain(&relays, "Other.Test").unwrap();
        assert_eq!(dns.mx.len(), 4);
        assert!(dns.mx.contains(&("mx6.example.com".to_string(), 5)));

        // No relay that takes mail: the server's own records
        assert_eq!(for_domain(&relays[3..5], "example.com"), None);
        assert_eq!(for_domain(&[], "example.com"), None);
    }

    #[test]
    fn send_through_leaves_the_server_out() {
        let mut through = relay(1, "mx1.example.com", 10);
        through.send_through = true;
        let dns = for_domain(&[through], "example.com").unwrap();
        assert!(!dns.server_sends);
    }

    #[test]
    fn spf_names_each_host() {
        let hosts = vec!["mx1.example.com".to_string(), "mail.example.com".into()];
        assert_eq!(
            spf_policy(&hosts).unwrap(),
            "v=spf1 a:mx1.example.com a:mail.example.com -all"
        );
        assert_eq!(spf_policy(&[]).unwrap(), "v=spf1 -all");
        let many: Vec<String> = (0..11).map(|i| format!("mx{i}.example.com")).collect();
        assert_eq!(spf_policy(&many), None);
        assert!(spf_policy(&many[..10]).is_some());
    }

    #[test]
    fn what_changes_the_records() {
        let base = vec![relay(1, "mx1.example.com", 10)];
        let hash = inputs_hash(&base);
        assert_ne!(hash, 0);

        // None in any record hashes as nothing
        let mut waiting = base.clone();
        waiting[0].join.relay_pin = None;
        assert_eq!(inputs_hash(&waiting), 0);
        assert_eq!(inputs_hash(&[]), 0);

        let mut renamed = base.clone();
        renamed[0].name = "edge".into();
        renamed[0].settings.max_recipients += 1;
        assert_eq!(inputs_hash(&renamed), hash, "not in any record");

        for change in [
            |r: &mut Relay| r.mx_preference = 20,
            |r: &mut Relay| r.inbound_only = true,
            |r: &mut Relay| r.send_through = true,
            |r: &mut Relay| r.settings.hostname = "mx9.example.com".into(),
            |r: &mut Relay| r.settings.domains = vec!["example.com".into()],
            |r: &mut Relay| r.enabled = false,
        ] {
            let mut changed = base.clone();
            change(&mut changed[0]);
            assert_ne!(inputs_hash(&changed), hash);
        }
    }
}
