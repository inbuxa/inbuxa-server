/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use std::{net::Ipv4Addr, time::Duration as StdDuration};

use common::network::dns::update::{DnsUpdater, follow_challenge_cname};
use dns_update::{DnsRecord, DnsRecordType, TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector};
use mail_auth::hickory_resolver::{
    TokioResolver,
    config::{ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
};
use registry::{
    schema::{
        enums::{IpProtocol, TsigAlgorithm},
        structs::{DnsServer, DnsServerTsig, SecretKey, SecretKeyValue},
    },
    types::duration::Duration,
};

use crate::utils::server::TestServer;

const ZONE: &str = "stalwart.test";
const KEY_B64: &str = "c3RhbHdhcnQtdGVzdC10c2lnLXNlY3JldC1rZXkxMjM0NTY3ODkw";

pub async fn test(test: &TestServer) {
    println!("Running RFC2136 (PowerDNS) tests...");
    crate::utils::containers::ensure_powerdns().await;

    let udp = DnsUpdater::build(dns_server(IpProtocol::Udp), test.server.core.clone())
        .await
        .expect("Failed to build UDP RFC2136 updater");

    // Create, replace and delete an A record over UDP (TSIG signed)
    let a_name = "rfc2136-a.stalwart.test";
    udp.updater
        .set_rrset(
            a_name,
            DnsRecordType::A,
            60,
            vec![DnsRecord::A(Ipv4Addr::new(10, 0, 0, 1))],
            ZONE,
        )
        .await
        .expect("set A");
    assert_eq!(
        list(&udp, a_name, DnsRecordType::A, 1).await,
        vec![DnsRecord::A(Ipv4Addr::new(10, 0, 0, 1))]
    );

    udp.updater
        .set_rrset(
            a_name,
            DnsRecordType::A,
            60,
            vec![DnsRecord::A(Ipv4Addr::new(10, 0, 0, 2))],
            ZONE,
        )
        .await
        .expect("replace A");
    assert_eq!(
        list(&udp, a_name, DnsRecordType::A, 1).await,
        vec![DnsRecord::A(Ipv4Addr::new(10, 0, 0, 2))]
    );

    udp.updater
        .set_rrset(a_name, DnsRecordType::A, 0, vec![], ZONE)
        .await
        .expect("delete A");
    assert!(list(&udp, a_name, DnsRecordType::A, 0).await.is_empty());

    // A name outside the zone is refused with a reason. hickory asserts the
    // name is inside the zone, and this used to panic the task (#310)
    let outside = "rfc2136-outside.example.org";
    let err = udp
        .set_rrset(
            ZONE,
            outside,
            DnsRecordType::TXT,
            vec![DnsRecord::TXT("outside".to_string())],
        )
        .await
        .expect_err("set outside the zone");
    assert!(
        err.contains("not in the DNS zone"),
        "unexpected error: {err}"
    );
    udp.delete_rrset(ZONE, outside, DnsRecordType::TXT)
        .await
        .expect_err("delete outside the zone");
    udp.list_rrset(ZONE, outside, DnsRecordType::TXT)
        .await
        .expect_err("list outside the zone");

    // DNS-01 follows a CNAME on the challenge name, hop by hop, to where the
    // record is written (#310)
    for (name, target) in [
        (
            "_acme-challenge.cname-310.stalwart.test",
            "acme-310.stalwart.test",
        ),
        (
            "_acme-challenge.hop-310.stalwart.test",
            "_acme-challenge.cname-310.stalwart.test",
        ),
    ] {
        udp.set_rrset(
            ZONE,
            name,
            DnsRecordType::CNAME,
            vec![DnsRecord::CNAME(format!("{target}."))],
        )
        .await
        .expect("set CNAME");
    }
    let resolver = powerdns_resolver();
    let mut followed = String::new();
    for _ in 0..20 {
        followed = follow_challenge_cname(&resolver, "_acme-challenge.hop-310.stalwart.test").await;
        if followed == "acme-310.stalwart.test" {
            break;
        }
        tokio::time::sleep(StdDuration::from_millis(50)).await;
    }
    assert_eq!(followed, "acme-310.stalwart.test");
    assert_eq!(
        follow_challenge_cname(&resolver, "_acme-challenge.plain-310.stalwart.test").await,
        "_acme-challenge.plain-310.stalwart.test"
    );
    for name in [
        "_acme-challenge.cname-310.stalwart.test",
        "_acme-challenge.hop-310.stalwart.test",
    ] {
        udp.delete_rrset(ZONE, name, DnsRecordType::CNAME)
            .await
            .expect("cleanup CNAME");
    }

    // Publish two TLSA records at the same owner in a single set_rrset call
    let tlsa_name = "_25._tcp.rfc2136-tlsa.stalwart.test";
    let leaf: Vec<u8> = (0..32).collect();
    let intermediate: Vec<u8> = (32..64).collect();
    udp.updater
        .set_rrset(
            tlsa_name,
            DnsRecordType::TLSA,
            60,
            vec![
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: leaf.clone(),
                }),
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneTa,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: intermediate.clone(),
                }),
            ],
            ZONE,
        )
        .await
        .expect("set TLSA");
    let tlsa = list(&udp, tlsa_name, DnsRecordType::TLSA, 2).await;
    let cert_datas: Vec<Vec<u8>> = tlsa
        .iter()
        .filter_map(|r| match r {
            DnsRecord::TLSA(t) => Some(t.cert_data.clone()),
            _ => None,
        })
        .collect();
    assert!(cert_datas.contains(&leaf), "leaf TLSA missing: {tlsa:?}");
    assert!(
        cert_datas.contains(&intermediate),
        "intermediate TLSA missing: {tlsa:?}"
    );
    udp.updater
        .set_rrset(tlsa_name, DnsRecordType::TLSA, 0, vec![], ZONE)
        .await
        .expect("cleanup TLSA");

    // The TCP transport must also attach the TSIG signer
    let tcp = DnsUpdater::build(dns_server(IpProtocol::Tcp), test.server.core.clone())
        .await
        .expect("Failed to build TCP RFC2136 updater");
    let txt_name = "rfc2136-txt.stalwart.test";
    tcp.updater
        .set_rrset(
            txt_name,
            DnsRecordType::TXT,
            60,
            vec![DnsRecord::TXT("rfc2136-tcp-signed".to_string())],
            ZONE,
        )
        .await
        .expect("set TXT over TCP");
    assert_eq!(
        list(&tcp, txt_name, DnsRecordType::TXT, 1).await,
        vec![DnsRecord::TXT("rfc2136-tcp-signed".to_string())]
    );
    tcp.updater
        .set_rrset(txt_name, DnsRecordType::TXT, 0, vec![], ZONE)
        .await
        .expect("cleanup TXT");
}

async fn list(
    updater: &DnsUpdater,
    name: &str,
    record_type: DnsRecordType,
    expected_len: usize,
) -> Vec<DnsRecord> {
    let mut latest = Vec::new();
    for _ in 0..20 {
        latest = updater
            .updater
            .list_rrset(name, record_type, ZONE)
            .await
            .unwrap_or_default();
        if latest.len() == expected_len {
            return latest;
        }
        tokio::time::sleep(StdDuration::from_millis(50)).await;
    }
    latest
}

fn dns_server(protocol: IpProtocol) -> DnsServer {
    DnsServer::Tsig(DnsServerTsig {
        host: "127.0.0.1".parse().unwrap(),
        port: 5300,
        key_name: "stalwart-update-key".to_string(),
        key: SecretKey::Value(SecretKeyValue {
            secret: KEY_B64.into(),
        }),
        protocol,
        tsig_algorithm: TsigAlgorithm::HmacSha256,
        description: "Test RFC2136 DNS server".to_string(),
        member_tenant_id: None,
        timeout: Duration::from_millis(10_000),
        ttl: Duration::from_millis(60_000),
        polling_interval: Duration::from_millis(100),
        propagation_timeout: Duration::from_millis(10_000),
        propagation_delay: None,
    })
}

fn powerdns_resolver() -> TokioResolver {
    let mut config = ResolverConfig::default();
    let mut connection = ConnectionConfig::new(ProtocolConfig::Udp);
    connection.port = 5300;
    config.add_name_server(NameServerConfig::new(
        "127.0.0.1".parse().unwrap(),
        true,
        vec![connection],
    ));
    let mut opts = ResolverOpts::default();
    opts.cache_size = 0;
    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .expect("Failed to build PowerDNS resolver")
}
