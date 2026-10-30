/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Outbound mail through relays, the downstream's side (relay spec,
//! "Outbound routing", RL-20, RL-24): whether mail goes through relays,
//! which of them this node can hand a message to, and the messages handed
//! to each until it reports a final status.
//!
//! A message handed over is kept under `o` + relay id (u32) + the relay's
//! `Outbound` id ([`Handed`]), as JSON, in the shared store: on a cluster
//! the node that follows a relay's statuses needn't be the one that handed
//! the message over.

use super::{
    FEATURE, Json, KIND_HANDED, Relay,
    link::{INBOUND_ID_MAX, is_inbound_id},
};
use inbuxa_relay_proto::types::Envelope;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

/// Why a relay didn't take a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// No relay will: the message is too large, or its sender isn't at
    /// one of the relays' domains. An SMTP reply, e.g. `552 5.3.4 ...`.
    Permanent(String),
    /// Not this relay, or not now: the link failed, or its spool is full.
    Temporary(String),
}

pub type HandOver<'a> = Pin<Box<dyn Future<Output = Result<String, Refused>> + Send + 'a>>;

pub type Call<'a> = Pin<Box<dyn Future<Output = Result<serde_json::Value, String>> + Send + 'a>>;

/// One relay link on this node, able to take a message: uploads it and
/// creates an `Outbound`, whose id it returns.
pub trait Sender: Send + Sync {
    fn hand_over(&self, message: Vec<u8>, envelope: Envelope) -> HandOver<'_>;

    /// One method on the relay's API, on its account: the answer's
    /// arguments, or why there are none (the relay's error included).
    fn call(&self, method: &'static str, args: serde_json::Value) -> Call<'_>;
}

/// A relay this node is linked to.
pub struct Linked {
    pub relay_id: u32,
    pub name: String,
    pub sender: Box<dyn Sender>,
}

/// The relays mail goes through, as this node sees them. Read from the
/// registry by the link service, and on first use.
#[derive(Default)]
pub struct Senders {
    state: Mutex<State>,
    next: AtomicUsize,
}

#[derive(Default)]
struct State {
    /// The relays were read at least once.
    known: bool,
    /// An enabled relay has `sendThrough` on (RL-24).
    send_through: bool,
    /// Enabled relays not marked `inboundOnly` (RL-20), by id, with their
    /// names as they are now: a rename doesn't restart the link.
    may_send: HashMap<u32, String>,
    linked: BTreeMap<u32, Arc<Linked>>,
}

impl Senders {
    /// Takes the relays as they are in the registry now.
    pub fn set_relays(&self, relays: &[Relay]) {
        let mut state = self.state.lock().expect("senders");
        state.known = true;
        state.send_through = relays.iter().any(|r| r.enabled && r.send_through);
        state.may_send = relays
            .iter()
            .filter(|r| r.enabled && !r.inbound_only)
            .map(|r| (r.id, r.name.trim().to_string()))
            .collect();
    }

    /// Whether the relays were read yet.
    pub fn known(&self) -> bool {
        self.state.lock().expect("senders").known
    }

    /// Reads the relays, if nothing has yet.
    pub async fn load(&self, data: &Store) -> trc::Result<()> {
        if !self.known() {
            let relays = super::all(data).await?;
            self.set_relays(&relays);
        }
        Ok(())
    }

    /// Whether every non-local recipient goes through a relay (RL-24). With
    /// none of them linked, mail waits in this server's queue (RL-20).
    pub fn sending(&self) -> bool {
        self.state.lock().expect("senders").send_through
    }

    pub fn link_up(&self, linked: Arc<Linked>) {
        self.state
            .lock()
            .expect("senders")
            .linked
            .insert(linked.relay_id, linked);
    }

    /// This node's link to a relay, while it is up, whether the relay
    /// sends mail or not.
    pub fn linked(&self, relay_id: u32) -> Option<Arc<Linked>> {
        self.state
            .lock()
            .expect("senders")
            .linked
            .get(&relay_id)
            .cloned()
    }

    /// Forgets a link, unless a newer one to the same relay replaced it.
    pub fn link_down(&self, linked: &Arc<Linked>) {
        let mut state = self.state.lock().expect("senders");
        if state
            .linked
            .get(&linked.relay_id)
            .is_some_and(|current| Arc::ptr_eq(current, linked))
        {
            state.linked.remove(&linked.relay_id);
        }
    }

    /// The relays to try for one message, in order: those this node is
    /// linked to and that may send, of those `named` when a route names
    /// some, each message starting with the next one in turn (RL-20, RL-24).
    pub fn candidates(&self, named: &[String]) -> Vec<Arc<Linked>> {
        let state = self.state.lock().expect("senders");
        let mut linked: Vec<Arc<Linked>> = state
            .linked
            .values()
            .filter(|l| {
                state
                    .may_send
                    .get(&l.relay_id)
                    .is_some_and(|name| named.is_empty() || named.iter().any(|n| n.trim() == name))
            })
            .cloned()
            .collect();
        if !linked.is_empty() {
            let first = self.next.fetch_add(1, Ordering::Relaxed) % linked.len();
            linked.rotate_left(first);
        }
        linked
    }
}

// ---- Messages handed over ---------------------------------------------------

/// A message handed to a relay: which queued message, and which of its
/// recipients, as the envelope named them.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Handed {
    /// The relay's `Outbound` id.
    pub id: String,
    pub queue_id: u64,
    pub queue_name: String,
    pub recipients: Vec<String>,
    pub at: u64,
}

fn handed_class(relay_id: u32, outbound_id: &[u8]) -> ValueClass {
    let mut key = Vec::with_capacity(6 + outbound_id.len());
    key.push(FEATURE);
    key.push(KIND_HANDED);
    key.extend_from_slice(&relay_id.to_be_bytes());
    key.extend_from_slice(outbound_id);
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

pub async fn record_handed(data: &Store, relay_id: u32, handed: &Handed) -> trc::Result<()> {
    if !is_inbound_id(&handed.id) {
        return Err(trc::StoreEvent::UnexpectedError
            .into_err()
            .details("A relay's outbound id isn't one")
            .ctx(trc::Key::Id, handed.id.clone()));
    }
    let mut batch = BatchBuilder::new();
    batch.set(
        handed_class(relay_id, handed.id.as_bytes()),
        Json(handed).serialize()?,
    );
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

/// The messages handed to a relay with no final status yet.
pub async fn handed(data: &Store, relay_id: u32) -> trc::Result<Vec<Handed>> {
    let mut handed = Vec::new();
    data.iterate(
        IterateParams::new(
            ValueKey::from(handed_class(relay_id, &[])),
            ValueKey::from(handed_class(relay_id, &[u8::MAX; INBOUND_ID_MAX + 1])),
        ),
        |_, value| {
            if let Ok(Json(one)) = Json::<Handed>::deserialize(value) {
                handed.push(one);
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    Ok(handed)
}

pub async fn forget_handed(data: &Store, relay_id: u32, ids: &[String]) -> trc::Result<()> {
    for chunk in ids.chunks(500) {
        let mut batch = BatchBuilder::new();
        for id in chunk {
            batch.clear(handed_class(relay_id, id.as_bytes()));
        }
        data.write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Nothing;

    impl Sender for Nothing {
        fn hand_over(&self, _: Vec<u8>, _: Envelope) -> HandOver<'_> {
            Box::pin(async { Err(Refused::Temporary("no".into())) })
        }

        fn call(&self, _: &'static str, _: serde_json::Value) -> Call<'_> {
            Box::pin(async { Err("no".into()) })
        }
    }

    fn relay(id: u32, send_through: bool, inbound_only: bool) -> Relay {
        let mut relay: Relay = serde_json::from_value(serde_json::json!({
            "name": format!("r{id}"),
            "address": "relay.example.com",
        }))
        .unwrap();
        relay.id = id;
        relay.send_through = send_through;
        relay.inbound_only = inbound_only;
        relay
    }

    fn linked(relay_id: u32) -> Arc<Linked> {
        Arc::new(Linked {
            relay_id,
            name: format!("r{relay_id}"),
            sender: Box::new(Nothing),
        })
    }

    #[test]
    fn rotation_skips_inbound_only() {
        let senders = Senders::default();
        assert!(!senders.known() && !senders.sending());
        // Off until a relay has sendThrough on
        senders.set_relays(&[relay(1, false, false), relay(2, false, true)]);
        assert!(senders.known() && !senders.sending());
        senders.set_relays(&[
            relay(1, true, false),
            relay(2, false, true),
            relay(3, false, false),
        ]);
        assert!(senders.sending());
        // Nothing linked: nothing to try, and the mail waits
        assert!(senders.candidates(&[]).is_empty());
        for id in [1, 2, 3] {
            senders.link_up(linked(id));
        }
        let mut firsts = Vec::new();
        for _ in 0..4 {
            let ids: Vec<u32> = senders.candidates(&[]).iter().map(|l| l.relay_id).collect();
            assert_eq!(ids.len(), 2, "{ids:?}");
            assert!(!ids.contains(&2), "inboundOnly: {ids:?}");
            firsts.push(ids[0]);
        }
        assert_eq!(firsts, [1, 3, 1, 3]);
    }

    #[test]
    fn an_old_link_leaves_a_new_one() {
        let senders = Senders::default();
        senders.set_relays(&[relay(1, true, false)]);
        let old = linked(1);
        let new = linked(1);
        senders.link_up(old.clone());
        senders.link_up(new.clone());
        senders.link_down(&old);
        assert_eq!(senders.candidates(&[]).len(), 1);
        senders.link_down(&new);
        assert!(senders.candidates(&[]).is_empty());
    }

    #[test]
    fn a_route_names_its_relays() {
        let senders = Senders::default();
        let mut renamed = relay(3, false, false);
        renamed.name = "east".into();
        senders.set_relays(&[relay(1, false, false), relay(2, false, true), renamed]);
        for id in [1, 2, 3] {
            senders.link_up(linked(id));
        }
        let ids = |named: &[&str]| -> Vec<u32> {
            let named: Vec<String> = named.iter().map(|n| n.to_string()).collect();
            let mut ids: Vec<u32> = senders
                .candidates(&named)
                .iter()
                .map(|l| l.relay_id)
                .collect();
            ids.sort();
            ids
        };
        assert_eq!(ids(&[]), [1, 3]);
        assert_eq!(ids(&["r1"]), [1]);
        // By the name it has now, not the one it was linked under
        assert_eq!(ids(&["east"]), [3]);
        assert!(ids(&["r3"]).is_empty());
        // inboundOnly sends nothing, named or not
        assert!(ids(&["r2"]).is_empty());
        assert_eq!(ids(&["r1", "east", "nowhere"]), [1, 3]);
    }
}
