/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    IterateParams, RegistryStore, RegistryStoreInner, Store, U16_LEN, U32_LEN, U64_LEN, ValueKey,
    write::{
        BatchBuilder, ValueClass,
        assert::AssertValue,
        key::{DeserializeBigEndian, KeySerializer},
        now,
    },
};
use registry::{
    schema::{enums::ClusterNodeStatus, structs::ClusterNode},
    types::datetime::UTCDateTime,
};
use std::{
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::Duration,
};
use trc::{AddContext, ClusterEvent};
use utils::snowflake::{MAX_NODE_ID, SnowflakeIdGenerator};

const STALE_NODE_TIMEOUT: u64 = 60 * 60; // 1 hour
const DEAD_NODE_TIMEOUT: u64 = 60 * 60 * 24; // 24 hours

// INBUXA: every node renews its lease once a minute, so the lease doubles as
// a heartbeat. A node not heard from in three minutes is reported Stale, which
// is what Cluster Health on the dashboard counts. Taking over a lease still
// needs the full hour of silence, so a node that is slow rather than gone
// never loses its id to another host.
const HEARTBEAT_INTERVAL: u64 = 60; // 1 minute
const UNRESPONSIVE_NODE_TIMEOUT: u64 = 3 * HEARTBEAT_INTERVAL;
const MAX_LEASE_RETRIES: u32 = 5;
// INBUXA: #458, see `release_renamed_lease`.
const RENAMED_LEASE_GRACE: u64 = 2 * HEARTBEAT_INTERVAL;
const HOSTNAME_MARKER: &str = "node-hostname";

struct NodeSlot {
    node_id: u16,
    hostname: String,
    last_renewal: u64,
    elapsed: u64,
    hash: u64,
}

struct NodeClaim {
    node_id: u16,
    assert: AssertValue,
}

impl RegistryStoreInner {
    pub(super) async fn acquire_node_id(&mut self) -> Result<(), String> {
        let (node_id, slots) = NodeSlot::acquire(&self.store, &self.env_hostname).await?;
        self.node_id.store(node_id, Ordering::Relaxed);
        self.remember_hostname().await;

        if let Err(err) = NodeSlot::release(
            &self.store,
            slots
                .iter()
                .filter(|slot| slot.node_id != node_id && slot.is_dead()),
        )
        .await
        {
            trc::error!(err.details("Failed to release expired node id leases"));
        }

        Ok(())
    }

    // INBUXA: #458. The lease is keyed by hostname, so renaming a server
    // (the installer sets the container's hostname to the mail host) left the
    // old name's lease behind, reported as a node not responding until it went
    // inactive a day later. Each node keeps the name it last leased under in a
    // file next to its local config. When that name changes, the old name's
    // lease is this node's own and is released once it stops renewing; see
    // `release_renamed_lease`. The file is best effort: a read-only config
    // directory only means a rename falls back to the 24-hour expiry.
    async fn remember_hostname(&mut self) {
        let path = hostname_marker(&self.local_path);
        if let Ok(previous) = tokio::fs::read_to_string(&path).await {
            let previous = previous.trim();
            if !previous.is_empty() && previous != self.env_hostname {
                self.renamed_from = Some((previous.to_string(), now()));
            }
        }
        if self.renamed_from.is_some() || !path.exists() {
            let _ = tokio::fs::write(&path, &self.env_hostname).await;
        }
    }
}

// INBUXA: #458, the file a node records its leased hostname in.
// It sits beside the local config file, or inside the directory when the
// path is one (as in the test harness).
fn hostname_marker(local_path: &Path) -> PathBuf {
    if local_path.is_dir() {
        local_path.join(HOSTNAME_MARKER)
    } else {
        local_path.with_file_name(HOSTNAME_MARKER)
    }
}

impl RegistryStore {
    pub fn node_id(&self) -> u16 {
        self.0.node_id.load(Ordering::Relaxed)
    }

    pub fn refresh_node_id_interval(&self) -> Duration {
        Duration::from_secs(HEARTBEAT_INTERVAL)
    }

    pub async fn cluster_node_list(&self) -> trc::Result<Vec<ClusterNode>> {
        NodeSlot::list(&self.0.store, now())
            .await
            .map(|slots| slots.into_iter().map(ClusterNode::from).collect())
    }

    pub async fn refresh_node_id_lease(&self) -> trc::Result<()> {
        let node_id = self.node_id();
        let slots = NodeSlot::list(&self.0.store, now())
            .await
            .caused_by(trc::location!())?;
        let assert = match slots.iter().find(|slot| slot.node_id == node_id) {
            Some(slot) if slot.is_owned_by(&self.0.env_hostname) => AssertValue::Hash(slot.hash),
            Some(slot) => {
                // INBUXA: another host took this id after the hour of silence,
                // so this node was cut off from the store for longer than
                // STALE_NODE_TIMEOUT. Keeping the id would mint snowflake ids
                // that collide with that host's. Step down and claim a fresh
                // id instead of only logging it.
                let (new_node_id, _) = NodeSlot::acquire(&self.0.store, &self.0.env_hostname)
                    .await
                    .map_err(|err| {
                        trc::StoreEvent::UnexpectedError
                            .into_err()
                            .details(err)
                            .ctx(trc::Key::Id, node_id)
                    })?;
                self.0.node_id.store(new_node_id, Ordering::Relaxed);
                SnowflakeIdGenerator::set_node_id(new_node_id as u64);

                trc::event!(
                    Cluster(ClusterEvent::NodeIdReassigned),
                    Id = new_node_id,
                    Hostname = slot.hostname.clone(),
                    Details = format!("Node id {node_id} lease is held by another host"),
                );

                return Ok(());
            }
            None => AssertValue::None,
        };

        let mut batch = BatchBuilder::new();
        batch.assert_value(ValueClass::NodeId(node_id), assert).set(
            ValueClass::NodeId(node_id),
            KeySerializer::new(self.0.env_hostname.len() + U64_LEN)
                .write(now())
                .write(&self.0.env_hostname)
                .finalize(),
        );

        self.0
            .store
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;

        self.release_renamed_lease(&slots).await
    }

    // INBUXA: #458. Drops the lease this node held under its previous
    // hostname once that lease has missed two renewals, before the dashboard
    // would report it as a node not responding. Only a lease last renewed
    // before this node started counts: the old name stops renewing when the
    // server is restarted under the new one. A host still running under that
    // name (two nodes sharing a config directory, say) renews after that, so
    // its lease is left to the usual expiry and still shows up when it stops.
    async fn release_renamed_lease(&self, slots: &[NodeSlot]) -> trc::Result<()> {
        let Some((previous, started)) = self.0.renamed_from.as_ref() else {
            return Ok(());
        };
        NodeSlot::release(
            &self.0.store,
            slots
                .iter()
                .filter(|slot| slot.is_renamed_from(previous, &self.0.env_hostname, *started)),
        )
        .await
        .caused_by(trc::location!())
    }

    pub async fn purge_dead_nodes(&self) -> trc::Result<()> {
        let node_id = self.node_id();
        let slots = NodeSlot::list(&self.0.store, now())
            .await
            .caused_by(trc::location!())?;

        if !slots.iter().any(|slot| {
            slot.node_id == node_id && slot.is_owned_by(&self.0.env_hostname) && !slot.is_stale()
        }) {
            Ok(())
        } else {
            NodeSlot::release(
                &self.0.store,
                slots
                    .iter()
                    .filter(|slot| slot.node_id != node_id && slot.is_dead()),
            )
            .await
        }
    }
}

impl NodeSlot {
    // Claims a node id for this hostname: its own slot if it still has one,
    // otherwise a stale one or the lowest free id. Returns the id and the
    // slots seen while claiming it.
    async fn acquire(store: &Store, hostname: &str) -> Result<(u16, Vec<NodeSlot>), String> {
        let mut retry_count = 0;
        loop {
            let now = now();
            let slots = NodeSlot::list(store, now)
                .await
                .map_err(|err| format!("Failed to iterate store: {err}"))?;
            let claim = NodeSlot::claim(&slots, hostname)?;
            let mut batch = BatchBuilder::new();

            batch
                .assert_value(ValueClass::NodeId(claim.node_id), claim.assert)
                .set(
                    ValueClass::NodeId(claim.node_id),
                    KeySerializer::new(hostname.len() + U64_LEN)
                        .write(now)
                        .write(hostname)
                        .finalize(),
                );

            match store.write(batch.build_all()).await {
                Ok(_) => return Ok((claim.node_id, slots)),
                Err(err) => {
                    if err.is_assertion_failure() && retry_count < MAX_LEASE_RETRIES {
                        retry_count += 1;
                        continue;
                    } else {
                        return Err(format!("Failed to write node id to store: {err}"));
                    }
                }
            }
        }
    }

    async fn list(store: &Store, now: u64) -> trc::Result<Vec<NodeSlot>> {
        let mut slots = Vec::new();

        store
            .iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::NodeId(0)),
                    ValueKey::from(ValueClass::NodeId(u16::MAX)),
                )
                .ascending(),
                |key, value| {
                    if key.len() == U16_LEN * 3 {
                        let node_id = key.deserialize_be_u16(U32_LEN)?;

                        match (
                            value.deserialize_be_u64(0),
                            value
                                .get(U64_LEN..)
                                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                                .filter(|text| !text.is_empty()),
                        ) {
                            (Ok(last_renewal), Some(hostname)) => {
                                slots.push(NodeSlot {
                                    node_id,
                                    hostname: hostname.to_string(),
                                    last_renewal,
                                    elapsed: now.saturating_sub(last_renewal),
                                    hash: xxhash_rust::xxh3::xxh3_64(value),
                                });
                            }
                            _ => {
                                trc::error!(
                                    trc::StoreEvent::DataCorruption
                                        .into_err()
                                        .details("Invalid node id lease")
                                        .ctx(trc::Key::Id, node_id)
                                );
                            }
                        }
                    }
                    Ok(true)
                },
            )
            .await
            .map(|_| slots)
    }

    fn claim(slots: &[NodeSlot], hostname: &str) -> Result<NodeClaim, String> {
        if let Some(slot) = slots
            .iter()
            .find(|slot| slot.is_owned_by(hostname) && slot.is_assignable())
            .or_else(|| {
                slots
                    .iter()
                    .find(|slot| slot.is_stale() && slot.is_assignable())
            })
        {
            return Ok(NodeClaim {
                node_id: slot.node_id,
                assert: AssertValue::Hash(slot.hash),
            });
        }

        let mut leased = slots
            .iter()
            .filter(|slot| !slot.is_stale())
            .map(|slot| slot.node_id)
            .collect::<Vec<_>>();
        leased.sort_unstable();

        let mut node_id = 0;
        for leased_id in leased {
            if leased_id > node_id {
                break;
            }
            node_id = leased_id.saturating_add(1);
            if node_id > MAX_NODE_ID {
                return Err(format!(
                    "Failed to obtain a node id: all {} ids are leased by active nodes",
                    MAX_NODE_ID as u32 + 1
                ));
            }
        }

        Ok(NodeClaim {
            node_id,
            assert: AssertValue::None,
        })
    }

    async fn release<'x>(
        store: &Store,
        slots: impl Iterator<Item = &'x NodeSlot>,
    ) -> trc::Result<()> {
        for slot in slots {
            let mut batch = BatchBuilder::new();
            batch
                .assert_value(
                    ValueClass::NodeId(slot.node_id),
                    AssertValue::Hash(slot.hash),
                )
                .clear(ValueClass::NodeId(slot.node_id));

            if let Err(err) = store.write(batch.build_all()).await
                && !err.is_assertion_failure()
            {
                return Err(err.caused_by(trc::location!()));
            }
        }

        Ok(())
    }

    fn is_owned_by(&self, hostname: &str) -> bool {
        self.hostname == hostname
    }

    // INBUXA: #458, a lease left under this node's previous hostname: last
    // renewed before this node started, and two renewals missed since.
    fn is_renamed_from(&self, previous: &str, current: &str, started: u64) -> bool {
        previous != current
            && self.is_owned_by(previous)
            && self.last_renewal <= started
            && self.elapsed > RENAMED_LEASE_GRACE
    }

    fn is_stale(&self) -> bool {
        self.elapsed > STALE_NODE_TIMEOUT
    }

    fn is_dead(&self) -> bool {
        self.elapsed > DEAD_NODE_TIMEOUT
    }

    fn is_responsive(&self) -> bool {
        self.elapsed <= UNRESPONSIVE_NODE_TIMEOUT
    }

    fn is_assignable(&self) -> bool {
        self.node_id <= MAX_NODE_ID
    }

    fn status(&self) -> ClusterNodeStatus {
        if self.is_dead() {
            ClusterNodeStatus::Inactive
        } else if self.is_responsive() {
            ClusterNodeStatus::Active
        } else {
            ClusterNodeStatus::Stale
        }
    }
}

impl From<NodeSlot> for ClusterNode {
    fn from(slot: NodeSlot) -> Self {
        ClusterNode {
            status: slot.status(),
            last_renewal: UTCDateTime::from_timestamp(slot.last_renewal.cast_signed()),
            node_id: slot.node_id as u64,
            hostname: slot.hostname,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(elapsed: u64) -> NodeSlot {
        NodeSlot {
            node_id: 1,
            hostname: "mx2.example.org".into(),
            last_renewal: 0,
            elapsed,
            hash: 0,
        }
    }

    #[test]
    fn status_follows_the_heartbeat() {
        assert_eq!(slot(0).status(), ClusterNodeStatus::Active);
        assert_eq!(
            slot(UNRESPONSIVE_NODE_TIMEOUT).status(),
            ClusterNodeStatus::Active
        );
        assert_eq!(
            slot(UNRESPONSIVE_NODE_TIMEOUT + 1).status(),
            ClusterNodeStatus::Stale
        );
        assert_eq!(slot(DEAD_NODE_TIMEOUT).status(), ClusterNodeStatus::Stale);
        assert_eq!(
            slot(DEAD_NODE_TIMEOUT + 1).status(),
            ClusterNodeStatus::Inactive
        );
    }

    fn renewed(hostname: &str, last_renewal: u64, now: u64) -> NodeSlot {
        NodeSlot {
            node_id: 1,
            hostname: hostname.into(),
            last_renewal,
            elapsed: now - last_renewal,
            hash: 0,
        }
    }

    #[test]
    fn a_renamed_node_drops_its_old_lease() {
        // mail.old.example renewed at 1000, the server came back as
        // mail.new.example at 1010.
        let (old, new, started) = ("mail.old.example", "mail.new.example", 1010);
        // Not before two renewals are missed...
        assert!(!renewed(old, 1000, 1000 + RENAMED_LEASE_GRACE).is_renamed_from(old, new, started));
        // ...and then well before the dashboard would call it stale.
        let left = renewed(old, 1000, 1001 + RENAMED_LEASE_GRACE);
        assert!(left.is_renamed_from(old, new, started));
        assert_eq!(left.status(), ClusterNodeStatus::Active);
        // Only the previous name's lease, and never this node's own.
        assert!(!renewed("mx2.example", 1000, 2000).is_renamed_from(old, new, started));
        assert!(!renewed(new, 1000, 2000).is_renamed_from(new, new, started));
    }

    #[test]
    fn a_live_host_under_the_old_name_keeps_its_lease() {
        // Renewed after this node started, so it isn't a lease left behind
        // by a rename: it goes through the usual Stale/Inactive path.
        let (old, new, started) = ("mx1.example", "mx2.example", 1010);
        assert!(!renewed(old, 1020, 5000).is_renamed_from(old, new, started));
    }

    #[test]
    fn a_silent_node_keeps_its_id_for_an_hour() {
        // Reported Stale after three minutes, but not free to take over.
        let quiet = slot(UNRESPONSIVE_NODE_TIMEOUT + 1);
        assert_eq!(quiet.status(), ClusterNodeStatus::Stale);
        assert!(!quiet.is_stale());
        assert!(slot(STALE_NODE_TIMEOUT + 1).is_stale());
    }

    fn owned(node_id: u16, hostname: &str, elapsed: u64) -> NodeSlot {
        NodeSlot {
            node_id,
            hostname: hostname.into(),
            last_renewal: 0,
            elapsed,
            hash: node_id as u64,
        }
    }

    #[test]
    fn a_node_whose_id_was_taken_claims_a_fresh_one() {
        // mx2 held id 1, was silent for over an hour, and mx3 took it over.
        // Back online, mx2 must not keep minting ids as node 1.
        let slots = vec![
            owned(0, "mail.example.org", 5),
            owned(1, "mx3.example.org", 5),
        ];
        let claim = NodeSlot::claim(&slots, "mx2.example.org").unwrap();
        assert_eq!(claim.node_id, 2);
        assert!(matches!(claim.assert, AssertValue::None));

        // Its own slot is preferred whenever it still has one.
        let slots = vec![
            owned(0, "mail.example.org", 5),
            owned(3, "mx2.example.org", 5),
        ];
        assert_eq!(
            NodeSlot::claim(&slots, "mx2.example.org").unwrap().node_id,
            3
        );
    }

    #[test]
    fn several_renewals_fit_before_a_node_looks_unresponsive() {
        assert!(UNRESPONSIVE_NODE_TIMEOUT >= 3 * HEARTBEAT_INTERVAL);
        assert!(HEARTBEAT_INTERVAL * 2 < STALE_NODE_TIMEOUT);
    }
}

// INBUXA: #458, a rename against a real store: the same config directory,
// the server restarted under a new hostname.
#[cfg(all(test, feature = "sqlite", feature = "test_mode"))]
mod rename_tests {
    use super::*;
    use crate::{RegistryStore, backend::sqlite::SqliteStore};

    struct Dir(PathBuf);

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn node(dir: &Path, store: &Store, hostname: &str) -> RegistryStoreInner {
        let mut inner = RegistryStoreInner::new(dir.join("config.json"));
        inner.store = store.clone();
        inner.env_hostname = hostname.to_string();
        inner
    }

    // Moves a lease's last renewal back, as if its host had gone quiet.
    async fn age(store: &Store, hostname: &str, last_renewal: u64) {
        let slot = NodeSlot::list(store, now())
            .await
            .unwrap()
            .into_iter()
            .find(|slot| slot.hostname == hostname)
            .unwrap();
        let mut batch = BatchBuilder::new();
        batch.set(
            ValueClass::NodeId(slot.node_id),
            KeySerializer::new(hostname.len() + U64_LEN)
                .write(last_renewal)
                .write(hostname)
                .finalize(),
        );
        store.write(batch.build_all()).await.unwrap();
    }

    async fn hostnames(store: &Store) -> Vec<String> {
        let mut names = NodeSlot::list(store, now())
            .await
            .unwrap()
            .into_iter()
            .map(|slot| slot.hostname)
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn temp_dir(name: &str) -> Dir {
        let dir = std::env::temp_dir().join(format!("inbuxa-458-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Dir(dir)
    }

    #[tokio::test]
    async fn a_renamed_server_drops_its_old_lease() {
        let dir = temp_dir("rename");
        let store = Store::SQLite(SqliteStore::open_memory().unwrap().into());

        let mut old = node(&dir.0, &store, "mail.old.example");
        old.acquire_node_id().await.unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.0.join(HOSTNAME_MARKER)).unwrap(),
            "mail.old.example"
        );

        // Shut down a little while ago, then started again as mail.new.example.
        age(&store, "mail.old.example", now() - 10).await;
        let mut new = node(&dir.0, &store, "mail.new.example");
        new.acquire_node_id().await.unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.0.join(HOSTNAME_MARKER)).unwrap(),
            "mail.new.example"
        );
        let new = RegistryStore(new.into());

        // Inside the grace period both leases are there.
        new.refresh_node_id_lease().await.unwrap();
        assert_eq!(
            hostnames(&store).await,
            ["mail.new.example", "mail.old.example"]
        );

        // Two missed renewals later, the old one is gone.
        age(&store, "mail.old.example", now() - RENAMED_LEASE_GRACE - 10).await;
        new.refresh_node_id_lease().await.unwrap();
        assert_eq!(hostnames(&store).await, ["mail.new.example"]);
    }

    #[tokio::test]
    async fn a_host_still_renewing_the_old_name_is_left_alone() {
        let dir = temp_dir("shared");
        let store = Store::SQLite(SqliteStore::open_memory().unwrap().into());

        let mut one = node(&dir.0, &store, "mx1.example");
        one.acquire_node_id().await.unwrap();
        // mx2 shares the config directory, so it reads mx1's name as its own
        // previous one...
        let mut two = node(&dir.0, &store, "mx2.example");
        two.acquire_node_id().await.unwrap();
        let (_, started) = two.renamed_from.clone().unwrap();
        let two = RegistryStore(two.into());

        // ...but mx1 renewed after mx2 started, then went quiet: a node down,
        // which the dashboard has to keep showing.
        age(&store, "mx1.example", started + 1).await;
        // Pretend the clock moved on so the grace period has passed.
        let slots = NodeSlot::list(&store, started + 1 + RENAMED_LEASE_GRACE + 60)
            .await
            .unwrap();
        two.release_renamed_lease(&slots).await.unwrap();
        assert_eq!(hostnames(&store).await, ["mx1.example", "mx2.example"]);
    }
}
