//! Tests for [`DnssecDnsHandle`] against a mock upstream returning canned responses.

use core::mem;
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use data_encoding::BASE32_DNSSEC;
use futures_util::{
    future,
    stream::{self, Stream},
};
use time::OffsetDateTime;

use super::DnssecDnsHandle;
use crate::{
    error::{DnsError, NetError},
    proto::{
        dnssec::{
            DigestType, DnssecSigner, Nsec3HashAlgorithm, Proof, PublicKeyBuf, SigningKey,
            TrustAnchors,
            crypto::Ed25519SigningKey,
            rdata::{DNSKEY, DNSSECRData, DS, NSEC, NSEC3, RRSIG},
        },
        op::{DnsRequest, DnsRequestOptions, DnsResponse, Message, Query, ResponseCode},
        rr::{
            DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType,
            rdata::{
                A, CNAME, NS, SOA, TLSA,
                tlsa::{CertUsage, Matching, Selector},
            },
        },
    },
    runtime::TokioRuntimeProvider,
    xfer::{DnsHandle, FirstAnswer},
};
use test_support::subscribe;

/// A server answering a DS query for an insecure zone with the child zone's own SOA record
/// (instead of the parent's) must not cause a validation loop, and the zone must be recognized
/// as insecure if its parent zone is insecure.
///
/// Regression test for <https://github.com/hickory-dns/hickory-dns/issues/3974>.
#[tokio::test]
async fn insecure_delegation_with_child_soa_in_ds_response() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Insecure);
    let child = Name::from_ascii("child.example.com.").unwrap();
    fixture.respond(&child, RecordType::DS, [], [unsigned_soa(&child)]);
    let (handle, queries) = fixture.build();

    let response = lookup_child_a(&handle).await.unwrap();
    assert_eq!(response.answers[0].proof, Proof::Insecure);
    assert_eq!(
        queries.count(&child, RecordType::DS),
        1,
        "the DS query for the child zone should only be sent once"
    );
}

/// A server answering a DS query for an insecure zone with an empty authority section must
/// still allow the zone to be recognized as insecure if its parent zone is insecure.
///
/// Regression test for <https://github.com/hickory-dns/hickory-dns/issues/3974>.
#[tokio::test]
async fn insecure_delegation_with_empty_ds_response() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Insecure);
    let child = Name::from_ascii("child.example.com.").unwrap();
    fixture.respond(&child, RecordType::DS, [], []);
    let (handle, _) = fixture.build();

    let response = lookup_child_a(&handle).await.unwrap();
    assert_eq!(response.answers[0].proof, Proof::Insecure);
}

/// The expected case: a DS query for an insecure zone is answered with the parent zone's SOA
/// record.
#[tokio::test]
async fn insecure_delegation_with_parent_soa_in_ds_response() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Insecure);
    let child = Name::from_ascii("child.example.com.").unwrap();
    let parent = Name::from_ascii("example.com.").unwrap();
    fixture.respond(&child, RecordType::DS, [], [unsigned_soa(&parent)]);
    let (handle, _) = fixture.build();

    let response = lookup_child_a(&handle).await.unwrap();
    assert_eq!(response.answers[0].proof, Proof::Insecure);
}

/// If the parent zone is secure, an unauthenticated DS response for the child zone must not be
/// accepted as proof of an insecure delegation, regardless of the SOA record it carries.
#[tokio::test]
async fn bogus_delegation_with_child_soa_in_ds_response() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Secure);
    let child = Name::from_ascii("child.example.com.").unwrap();
    fixture.respond(&child, RecordType::DS, [], [unsigned_soa(&child)]);
    let (handle, _) = fixture.build();

    let response = lookup_child_a(&handle).await.unwrap();
    assert_eq!(response.answers[0].proof, Proof::Bogus);
}

/// If the parent zone is secure, an empty DS response for the child zone must not be accepted
/// as proof of an insecure delegation.
#[tokio::test]
async fn bogus_delegation_with_empty_ds_response() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Secure);
    let child = Name::from_ascii("child.example.com.").unwrap();
    fixture.respond(&child, RecordType::DS, [], []);
    let (handle, _) = fixture.build();

    let response = lookup_child_a(&handle).await.unwrap();
    assert_eq!(response.answers[0].proof, Proof::Bogus);
}

/// A validating handle sets the CD bit on every query it sends upstream: the query being
/// validated and the DNSKEY and DS queries it makes through `lookup()`.
///
/// RFC 6840 section 5.9: validating resolvers SHOULD set the CD bit on every upstream query.
/// Regression test for <https://github.com/hickory-dns/hickory-dns/issues/3966>.
#[tokio::test]
async fn validating_queries_set_checking_disabled() -> Result<(), NetError> {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Insecure);
    let child = Name::from_ascii("child.example.com.")?;
    let parent = Name::from_ascii("example.com.")?;
    fixture.respond(&child, RecordType::DS, [], [unsigned_soa(&parent)]);
    let (handle, queries) = fixture.build();

    let response = lookup_child_a(&handle).await?;
    assert_eq!(
        response.answers.first().map(|record| record.proof),
        Some(Proof::Insecure)
    );

    let logged = mem::take(&mut *queries.0.lock().unwrap_or_else(PoisonError::into_inner));
    for record_type in [RecordType::A, RecordType::DNSKEY, RecordType::DS] {
        assert!(
            logged
                .iter()
                .any(|entry| entry.query.query_type == record_type),
            "expected at least one {record_type} query upstream"
        );
    }
    let cleared = logged
        .iter()
        .filter(|entry| !entry.checking_disabled)
        .map(|entry| &entry.query)
        .collect::<Vec<_>>();
    assert!(
        cleared.is_empty(),
        "queries sent upstream with CD=0: {cleared:?}"
    );
    Ok(())
}

/// A zone without NS records at its apex must not be mistaken for part of its signed parent zone.
///
/// Regression test for <https://github.com/hickory-dns/hickory-dns/issues/4027>.
#[tokio::test]
async fn insecure_delegation_without_apex_ns() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Insecure);
    let com = Name::from_ascii("com.").unwrap();
    let example = Name::from_ascii("example.com.").unwrap();
    let www = Name::from_ascii("www.example.com.").unwrap();
    fixture.respond(&com, RecordType::NS, [ns(&com)], []);
    fixture.respond(&example, RecordType::NS, [], [unsigned_soa(&example)]);
    fixture.respond(&www, RecordType::NS, [], [unsigned_soa(&example)]);
    fixture.respond(&www, RecordType::DS, [], [unsigned_soa(&example)]);
    fixture.respond(&www, RecordType::A, [a(&www)], []);
    let (handle, _) = fixture.build();

    let response = handle
        .lookup(
            Query::query(www, RecordType::A),
            DnsRequestOptions::default(),
        )
        .first_answer()
        .await
        .unwrap();
    assert_eq!(response.answers[0].proof, Proof::Insecure);
}

// A CNAME'd TLSA answer (RFC 7672 3.1.2) with the target's NSEC record in the authority section.
#[tokio::test]
async fn positive_answer_with_unrelated_nsec() {
    subscribe();

    let fixture = MockHandleBuilder::new(Parent::Secure);
    let target = Name::from_ascii("tlsa201._dane.example.com.").unwrap();
    let nsec = NSEC::new(
        Name::from_ascii("tlsa202._dane.example.com.").unwrap(),
        [RecordType::TLSA, RecordType::RRSIG, RecordType::NSEC],
    );
    let authorities = fixture.sign_example([Record::from_rdata(
        target,
        TTL,
        RData::DNSSEC(DNSSECRData::NSEC(nsec)),
    )]);
    let (handle, _) = fixture.with_cname_tlsa(authorities).build();

    assert_secure(lookup_tlsa(&handle).await);
}

// Same as above, with an unrelated NSEC3 record in the authority section.
#[tokio::test]
async fn positive_answer_with_unrelated_nsec3() {
    subscribe();

    let fixture = MockHandleBuilder::new(Parent::Secure);
    let owner_hash = nsec3_hash(&Name::from_ascii("tlsa201._dane.example.com.").unwrap());
    let mut next_hash = owner_hash.clone();
    for byte in next_hash.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
    let nsec3 = NSEC3::new(
        Nsec3HashAlgorithm::SHA1,
        false,
        0,
        Vec::new(),
        next_hash,
        [RecordType::TLSA, RecordType::RRSIG],
    );
    let owner = Name::from_ascii(BASE32_DNSSEC.encode(&owner_hash))
        .unwrap()
        .append_domain(fixture.example.signer_name())
        .unwrap();
    let authorities = fixture.sign_example([Record::from_rdata(
        owner,
        TTL,
        RData::DNSSEC(DNSSECRData::NSEC3(nsec3)),
    )]);
    let (handle, _) = fixture.with_cname_tlsa(authorities).build();

    assert_secure(lookup_tlsa(&handle).await);
}

// A wildcard expansion whose authority section only has an unrelated NSEC record.
#[tokio::test]
async fn wildcard_answer_with_unrelated_nsec() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Secure);
    let authorities = fixture.unrelated_nsec();
    let answers = fixture.wildcard_a(&wildcard_host());
    fixture.respond(&wildcard_host(), RecordType::A, answers, authorities);
    let (handle, _) = fixture.build();

    assert_bogus(lookup(&handle, wildcard_host(), RecordType::A).await);
}

// A wildcard expansion without any denial records.
#[tokio::test]
async fn wildcard_answer_without_nsec() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Secure);
    let answers = fixture.wildcard_a(&wildcard_host());
    fixture.respond(&wildcard_host(), RecordType::A, answers, []);
    let (handle, _) = fixture.build();

    assert_bogus(lookup(&handle, wildcard_host(), RecordType::A).await);
}

// A wildcard expansion with an NSEC record covering the next closer name.
#[tokio::test]
async fn wildcard_answer_with_next_closer_proof() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Secure);
    let nsec = NSEC::new(
        Name::from_ascii("z.wild.example.com.").unwrap(),
        [RecordType::A, RecordType::RRSIG, RecordType::NSEC],
    );
    let authorities = fixture.sign_example([Record::from_rdata(
        Name::from_ascii("a.wild.example.com.").unwrap(),
        TTL,
        RData::DNSSEC(DNSSECRData::NSEC(nsec)),
    )]);
    let answers = fixture.wildcard_a(&wildcard_host());
    fixture.respond(&wildcard_host(), RecordType::A, answers, authorities);
    let (handle, _) = fixture.build();

    assert_secure(lookup(&handle, wildcard_host(), RecordType::A).await);
}

// A wildcard-expanded CNAME, not the queried RRset itself, still needs a next closer proof.
#[tokio::test]
async fn wildcard_cname_with_unrelated_nsec() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Secure);
    let target = Name::from_ascii("www.example.com.").unwrap();
    let cname = Record::from_rdata(
        Name::from_ascii("*.wild.example.com.").unwrap(),
        TTL,
        RData::CNAME(CNAME(target.clone())),
    );
    let mut answers = fixture.expand_wildcard(cname, &wildcard_host());
    answers.extend(fixture.sign_example([a(&target)]));
    let authorities = fixture.unrelated_nsec();
    fixture.respond(&wildcard_host(), RecordType::A, answers, authorities);
    let (handle, _) = fixture.build();

    assert_bogus(lookup(&handle, wildcard_host(), RecordType::A).await);
}

fn assert_secure(result: Result<DnsResponse, NetError>) {
    let response = result.expect("response should validate");
    assert!(!response.answers.is_empty());
    for record in &response.answers {
        assert_eq!(record.proof, Proof::Secure, "{record}");
    }
}

fn assert_bogus(result: Result<DnsResponse, NetError>) {
    match result {
        Err(NetError::Dns(DnsError::Nsec { proof, .. })) => assert_eq!(proof, Proof::Bogus),
        other => panic!("expected a bogus NSEC proof, got {other:?}"),
    }
}

fn wildcard_host() -> Name {
    Name::from_ascii("host.wild.example.com.").unwrap()
}

fn nsec3_hash(name: &Name) -> Vec<u8> {
    Nsec3HashAlgorithm::SHA1
        .hash(&[], name, 0)
        .unwrap()
        .as_ref()
        .to_vec()
}

async fn lookup_tlsa(handle: &DnssecDnsHandle<MockHandle>) -> Result<DnsResponse, NetError> {
    lookup(
        handle,
        Name::from_ascii("_25._tcp.mx.example.com.").unwrap(),
        RecordType::TLSA,
    )
    .await
}

async fn lookup(
    handle: &DnssecDnsHandle<MockHandle>,
    name: Name,
    record_type: RecordType,
) -> Result<DnsResponse, NetError> {
    handle
        .lookup(
            Query::query(name, record_type),
            DnsRequestOptions::default(),
        )
        .first_answer()
        .await
}

/// Failed DS queries below an insecure delegation must not prevent the zone from being
/// recognized as insecure.
#[tokio::test]
async fn insecure_delegation_with_failed_ds_queries() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Insecure);
    let child = Name::from_ascii("child.example.com.").unwrap();
    let www = Name::from_ascii("www.child.example.com.").unwrap();
    fixture.fail(&www, RecordType::DS);
    fixture.fail(&child, RecordType::DS);
    let (handle, _) = fixture.build();

    let response = lookup_child_a(&handle).await.unwrap();
    assert_eq!(response.answers[0].proof, Proof::Insecure);
}

/// Failed DS queries below a secure delegation must not be treated as an insecure delegation.
#[tokio::test]
async fn bogus_delegation_with_failed_ds_queries() {
    subscribe();

    let mut fixture = MockHandleBuilder::new(Parent::Secure);
    let child = Name::from_ascii("child.example.com.").unwrap();
    let www = Name::from_ascii("www.child.example.com.").unwrap();
    fixture.fail(&www, RecordType::DS);
    fixture.fail(&child, RecordType::DS);
    let (handle, _) = fixture.build();

    let response = lookup_child_a(&handle).await.unwrap();
    assert_eq!(response.answers[0].proof, Proof::Bogus);
}

async fn lookup_child_a(handle: &DnssecDnsHandle<MockHandle>) -> Result<DnsResponse, NetError> {
    let name = Name::from_ascii("www.child.example.com.").unwrap();
    handle
        .lookup(
            Query::query(name, RecordType::A),
            DnsRequestOptions::default(),
        )
        .first_answer()
        .await
}

/// A signed root zone and a signed `com.` zone, delegating to `example.com.`, which in turn
/// delegates to `child.example.com.`. Both `example.com.` and `child.example.com.` are unsigned
/// zones, and `www.child.example.com.` has an A record.
///
/// If the `parent` configuration value is [`Parent::Secure`], `com.` zone will include a DS
/// record for the `example.com.` zone, establishing a secure delegation, even though the
/// `example.com.` zone's records are unsigned.
struct MockHandleBuilder {
    root: DnssecSigner,
    example: DnssecSigner,
    responses: HashMap<(LowerName, RecordType), Message>,
}

impl MockHandleBuilder {
    fn new(parent: Parent) -> Self {
        let key =
            Ed25519SigningKey::from_pkcs8(&Ed25519SigningKey::generate_pkcs8().unwrap()).unwrap();
        let public_key = key.to_public_key().unwrap();
        let root = DnssecSigner::new(
            DNSKEY::from_key(&public_key),
            Box::new(key),
            Name::root(),
            Duration::from_secs(86400),
        );

        let key =
            Ed25519SigningKey::from_pkcs8(&Ed25519SigningKey::generate_pkcs8().unwrap()).unwrap();
        let example_public_key = key.to_public_key().unwrap();
        let example = DnssecSigner::new(
            DNSKEY::from_key(&example_public_key),
            Box::new(key),
            Name::from_ascii("example.com.").unwrap(),
            Duration::from_secs(86400),
        );

        let mut new = Self {
            root,
            example,
            responses: HashMap::default(),
        };

        let key =
            Ed25519SigningKey::from_pkcs8(&Ed25519SigningKey::generate_pkcs8().unwrap()).unwrap();
        let com_public_key = key.to_public_key().unwrap();
        let com = DnssecSigner::new(
            DNSKEY::from_key(&com_public_key),
            Box::new(key),
            Name::from_ascii("com.").unwrap(),
            Duration::from_secs(86400),
        );

        let example = new.example.signer_name().clone();
        let child = Name::from_ascii("child.example.com.").unwrap();
        let www = Name::from_ascii("www.child.example.com.").unwrap();

        new.respond(
            &new.root.signer_name().clone(),
            RecordType::DNSKEY,
            sign([dnskey(&new.root)], &new.root),
            [],
        );
        new.respond(
            com.signer_name(),
            RecordType::DS,
            sign([ds(&com, &com_public_key)], &new.root),
            [],
        );
        new.respond(
            com.signer_name(),
            RecordType::DNSKEY,
            sign([dnskey(&com)], &com),
            [],
        );
        new.respond(&example, RecordType::NS, [ns(&example)], []);

        match parent {
            Parent::Insecure => {
                let mut authorities = sign([unsigned_soa(com.signer_name())], &com);
                authorities.extend(sign(
                    [Record::from_rdata(
                        example.clone(),
                        TTL,
                        RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                            Name::from_ascii("example0.com.").unwrap(),
                            [RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
                        ))),
                    )],
                    &com,
                ));
                new.respond(&example, RecordType::DS, [], authorities);
            }
            Parent::Secure => {
                let records = sign([ds(&new.example, &example_public_key)], &com);
                new.respond(&example, RecordType::DS, records, []);
                let records = sign([dnskey(&new.example)], &new.example);
                new.respond(&example, RecordType::DNSKEY, records, []);
            }
        }

        new.respond(&child, RecordType::NS, [ns(&child)], []);
        new.respond(&www, RecordType::NS, [], []);
        new.respond(&www, RecordType::DS, [], [unsigned_soa(&child)]);
        new.respond(&www, RecordType::A, [a(&www)], []);
        new
    }

    fn respond(
        &mut self,
        name: &Name,
        record_type: RecordType,
        answers: impl IntoIterator<Item = Record>,
        authorities: impl IntoIterator<Item = Record>,
    ) {
        let mut message = Message::query();
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answers(answers);
        message.add_authorities(authorities);
        self.responses
            .insert((LowerName::from(name), record_type), message);
    }

    fn sign_example(&self, records: impl IntoIterator<Item = Record>) -> Vec<Record> {
        sign(records, &self.example)
    }

    /// Sign a record owned by a wildcard name, and rename it as if it were expanded to `name`.
    fn expand_wildcard(&self, record: Record, name: &Name) -> Vec<Record> {
        let mut records = self.sign_example([record]);
        for record in &mut records {
            record.name = name.clone();
        }
        records
    }

    fn wildcard_a(&self, name: &Name) -> Vec<Record> {
        self.expand_wildcard(a(&Name::from_ascii("*.wild.example.com.").unwrap()), name)
    }

    fn unrelated_nsec(&self) -> Vec<Record> {
        let nsec = NSEC::new(
            Name::from_ascii("tlsa202._dane.example.com.").unwrap(),
            [RecordType::TLSA, RecordType::RRSIG, RecordType::NSEC],
        );
        self.sign_example([Record::from_rdata(
            Name::from_ascii("tlsa201._dane.example.com.").unwrap(),
            TTL,
            RData::DNSSEC(DNSSECRData::NSEC(nsec)),
        )])
    }

    /// Answer `_25._tcp.mx.example.com. TLSA` with a CNAME to `tlsa201._dane.example.com.` and
    /// the TLSA record at the target.
    fn with_cname_tlsa(mut self, authorities: Vec<Record>) -> Self {
        let alias = Name::from_ascii("_25._tcp.mx.example.com.").unwrap();
        let target = Name::from_ascii("tlsa201._dane.example.com.").unwrap();
        let mut answers = self.sign_example([Record::from_rdata(
            alias.clone(),
            TTL,
            RData::CNAME(CNAME(target.clone())),
        )]);
        answers.extend(self.sign_example([Record::from_rdata(
            target,
            TTL,
            RData::TLSA(TLSA::new(
                CertUsage::DaneEe,
                Selector::Spki,
                Matching::Sha256,
                vec![0; 32],
            )),
        )]));
        self.respond(&alias, RecordType::TLSA, answers, authorities);
        self
    }

    fn fail(&mut self, name: &Name, record_type: RecordType) {
        let mut message = Message::query();
        message.metadata.response_code = ResponseCode::ServFail;
        self.responses
            .insert((LowerName::from(name), record_type), message);
    }

    fn build(self) -> (DnssecDnsHandle<MockHandle>, QueryLog) {
        let Self {
            root, responses, ..
        } = self;
        let queries = QueryLog::default();
        let handle = MockHandle {
            responses: Arc::new(responses),
            queries: queries.clone(),
        };

        let mut anchors = TrustAnchors::empty();
        anchors.insert(&root.key().to_public_key().unwrap());

        (
            DnssecDnsHandle::with_trust_anchor(handle, Arc::new(anchors)),
            queries,
        )
    }
}

#[derive(Clone, Copy)]
enum Parent {
    Insecure,
    Secure,
}

/// Sign the given RRset with this zone's key, returning the records and their RRSIG.
fn sign(records: impl IntoIterator<Item = Record>, signer: &DnssecSigner) -> Vec<Record> {
    let mut records = records.into_iter().collect::<Vec<_>>();
    let first = records.first().expect("RRset must not be empty");
    let mut rrset = RecordSet::with_ttl(first.name.clone(), first.record_type(), TTL);
    for record in &records {
        rrset.insert(record.clone(), 0);
    }

    let inception = OffsetDateTime::now_utc() - Duration::from_secs(3600);
    let rrsig = RRSIG::from_rrset(&rrset, DNSClass::IN, inception, signer).unwrap();
    records.push(Record::from_rdata(
        first.name.clone(),
        TTL,
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
    ));
    records
}

fn ds(signer: &DnssecSigner, pub_key: &PublicKeyBuf) -> Record {
    let ds = DS::from_key(pub_key, signer.signer_name(), DigestType::SHA256).unwrap();
    Record::from_rdata(
        signer.signer_name().clone(),
        TTL,
        RData::DNSSEC(DNSSECRData::DS(ds)),
    )
}

fn dnskey(signer: &DnssecSigner) -> Record {
    Record::from_rdata(
        signer.signer_name().clone(),
        TTL,
        RData::DNSSEC(DNSSECRData::DNSKEY(signer.to_dnskey())),
    )
}

fn unsigned_soa(name: &Name) -> Record {
    Record::from_rdata(
        name.clone(),
        TTL,
        RData::SOA(SOA::new(
            Name::from_ascii("ns.")
                .unwrap()
                .append_domain(name)
                .unwrap(),
            Name::from_ascii("admin.")
                .unwrap()
                .append_domain(name)
                .unwrap(),
            1,
            3600,
            3600,
            3600,
            3600,
        )),
    )
}

fn ns(name: &Name) -> Record {
    Record::from_rdata(
        name.clone(),
        TTL,
        RData::NS(NS(Name::from_ascii("ns.")
            .unwrap()
            .append_domain(name)
            .unwrap())),
    )
}

fn a(name: &Name) -> Record {
    Record::from_rdata(name.clone(), TTL, RData::A(A(Ipv4Addr::new(192, 0, 2, 1))))
}

#[derive(Clone, Default)]
struct QueryLog(Arc<Mutex<Vec<LoggedQuery>>>);

/// A query the mock upstream received, with the CD bit of the request that carried it.
struct LoggedQuery {
    query: Query,
    checking_disabled: bool,
}

impl QueryLog {
    fn count(&self, name: &Name, record_type: RecordType) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|logged| &logged.query.name == name && logged.query.query_type == record_type)
            .count()
    }
}

#[derive(Clone)]
struct MockHandle {
    responses: Arc<HashMap<(LowerName, RecordType), Message>>,
    queries: QueryLog,
}

impl DnsHandle for MockHandle {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send>>;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        let query = request.queries[0].clone();
        self.queries
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(LoggedQuery {
                query: query.clone(),
                checking_disabled: request.metadata.checking_disabled,
            });

        let key = (LowerName::from(&query.name), query.query_type);
        let Some(message) = self.responses.get(&key) else {
            return Box::pin(stream::once(future::err(NetError::from(format!(
                "no canned response for {query}"
            )))));
        };

        if message.response_code != ResponseCode::NoError {
            return Box::pin(stream::once(future::err(NetError::from(
                DnsError::ResponseCode(message.response_code),
            ))));
        }

        let mut message = message.clone();
        message.metadata.id = request.metadata.id;
        message.add_query(query);
        let response = DnsResponse::from_message(message.into_response()).unwrap();
        Box::pin(stream::once(future::ok(response)))
    }
}

const TTL: u32 = 3600;
