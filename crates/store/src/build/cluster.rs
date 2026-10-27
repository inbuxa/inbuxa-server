/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, RegistryStore, RegistryStoreInner, Store, U64_LEN, ValueKey,
    write::{
        BatchBuilder, MergeResult, ValueClass,
        assert::AssertValue,
        key::{KeySerializer, node_id_from_key},
        now,
    },
};
use compact_str::CompactString;
use registry::{
    schema::{enums::ClusterNodeStatus, structs::ClusterNode},
    types::datetime::UTCDateTime,
};
use std::time::Duration;
use trc::AddContext;
use utils::snowflake::MAX_NODE_ID;

const STALE_NODE_TIMEOUT: u64 = 60 * 60; // 1 hour
const DEAD_NODE_TIMEOUT: u64 = 60 * 60 * 24; // 24 hours
const MAX_LEASE_RETRIES: u32 = 5;

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

struct NodeLease<'x> {
    last_renewal: u64,
    hostname: &'x str,
}

impl RegistryStoreInner {
    pub(super) async fn acquire_node_id(&mut self) -> Result<(), String> {
        let mut retry_count = 0;
        let slots = loop {
            let now = now();
            let slots = NodeSlot::list(&self.store, now)
                .await
                .map_err(|err| format!("Failed to iterate store: {err}"))?;
            let claim = NodeSlot::claim(&slots, &self.env_hostname)?;
            let mut batch = BatchBuilder::new();

            batch
                .assert_value(ValueClass::NodeId(claim.node_id), claim.assert)
                .set(
                    ValueClass::NodeId(claim.node_id),
                    NodeLease {
                        last_renewal: now,
                        hostname: &self.env_hostname,
                    }
                    .serialize(),
                );

            match self.store.write_batch(&mut batch).await {
                Ok(_) => {
                    self.node_id = claim.node_id;
                    break slots;
                }
                Err(err) => {
                    if err.is_assertion_failure() && retry_count < MAX_LEASE_RETRIES {
                        retry_count += 1;
                        continue;
                    } else {
                        return Err(format!("Failed to write node id to store: {err}"));
                    }
                }
            }
        };

        if let Err(err) = NodeSlot::release(
            &self.store,
            slots
                .iter()
                .filter(|slot| slot.node_id != self.node_id && slot.is_dead()),
        )
        .await
        {
            trc::error!(err.details("Failed to release expired node id leases"));
        }

        Ok(())
    }
}

impl RegistryStore {
    pub fn node_id(&self) -> u16 {
        self.0.node_id
    }

    pub fn refresh_node_id_interval(&self) -> Duration {
        Duration::from_secs(STALE_NODE_TIMEOUT / 2)
    }

    pub async fn cluster_node_list(&self) -> trc::Result<Vec<ClusterNode>> {
        NodeSlot::list(&self.0.store, now())
            .await
            .map(|slots| slots.into_iter().map(ClusterNode::from).collect())
    }

    pub async fn refresh_node_id_lease(&self) -> trc::Result<()> {
        let node_id = self.0.node_id;
        let hostname = self.0.env_hostname.clone();
        let last_renewal = now();

        let mut batch = BatchBuilder::new();
        batch.merge_fnc(ValueClass::NodeId(node_id), move |_, value| {
            NodeLease {
                last_renewal,
                hostname: &hostname,
            }
            .renew(node_id, value)
        });

        self.0
            .store
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())
            .map(|_| ())
    }

    pub async fn purge_dead_nodes(&self) -> trc::Result<()> {
        let node_id = self.0.node_id;
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
                    if let Some(node_id) = node_id_from_key(key) {
                        match NodeLease::parse(value) {
                            Some(lease) => {
                                slots.push(NodeSlot {
                                    node_id,
                                    hostname: lease.hostname.to_string(),
                                    last_renewal: lease.last_renewal,
                                    elapsed: now.saturating_sub(lease.last_renewal),
                                    hash: xxhash_rust::xxh3::xxh3_64(value),
                                });
                            }
                            None => {
                                trc::error!(
                                    trc::StoreEvent::DataCorruption
                                        .into_err()
                                        .details("Invalid node id lease")
                                        .ctx(trc::Key::NodeId, node_id)
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
        let mut batch = BatchBuilder::new();
        for slot in slots {
            let hash = slot.hash;
            batch.merge_fnc(ValueClass::NodeId(slot.node_id), move |_, value| {
                Ok(NodeSlot::release_if_unchanged(hash, value))
            });
        }

        if batch.is_empty() {
            Ok(())
        } else {
            store
                .write_batch(&mut batch)
                .await
                .caused_by(trc::location!())
                .map(|_| ())
        }
    }

    fn release_if_unchanged(hash: u64, value: Option<&[u8]>) -> MergeResult {
        if value.is_some_and(|value| xxhash_rust::xxh3::xxh3_64(value) == hash) {
            MergeResult::Delete
        } else {
            MergeResult::Skip
        }
    }

    fn is_owned_by(&self, hostname: &str) -> bool {
        self.hostname == hostname
    }

    fn is_stale(&self) -> bool {
        self.elapsed > STALE_NODE_TIMEOUT
    }

    fn is_dead(&self) -> bool {
        self.elapsed > DEAD_NODE_TIMEOUT
    }

    fn is_assignable(&self) -> bool {
        self.node_id <= MAX_NODE_ID
    }

    fn status(&self) -> ClusterNodeStatus {
        if self.is_dead() {
            ClusterNodeStatus::Inactive
        } else if self.is_stale() {
            ClusterNodeStatus::Stale
        } else {
            ClusterNodeStatus::Active
        }
    }
}

impl<'x> NodeLease<'x> {
    fn parse(value: &'x [u8]) -> Option<Self> {
        let (last_renewal, hostname) = value.split_first_chunk::<U64_LEN>()?;
        let hostname = std::str::from_utf8(hostname)
            .ok()
            .filter(|hostname| !hostname.is_empty())?;

        Some(NodeLease {
            last_renewal: u64::from_be_bytes(*last_renewal),
            hostname,
        })
    }

    fn serialize(&self) -> Vec<u8> {
        KeySerializer::new(self.hostname.len() + U64_LEN)
            .write(self.last_renewal)
            .write(self.hostname)
            .finalize()
    }

    fn renew(&self, node_id: u16, current: Option<&[u8]>) -> trc::Result<MergeResult> {
        if let Some(current) = current {
            match NodeLease::parse(current) {
                Some(lease) if lease.hostname == self.hostname => {}
                Some(lease) => {
                    return Err(trc::StoreEvent::AssertValueFailed
                        .into_err()
                        .details("Node id lease is held by another host")
                        .ctx(trc::Key::NodeId, node_id)
                        .ctx(trc::Key::Hostname, CompactString::from(lease.hostname)));
                }
                None => {
                    return Err(trc::StoreEvent::AssertValueFailed
                        .into_err()
                        .details("Invalid node id lease")
                        .ctx(trc::Key::NodeId, node_id));
                }
            }
        }

        Ok(MergeResult::Update(self.serialize()))
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

