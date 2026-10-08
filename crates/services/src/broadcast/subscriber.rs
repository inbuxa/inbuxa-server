/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::broadcast::{BROADCAST_TOPIC, BroadcastBatch};
use common::{
    BuildServer, Inner,
    ipc::{BroadcastEvent, PushEvent, PushNotification, QueueEvent, RegistryChange},
};
use registry::{schema::prelude::ObjectType, types::EnumImpl};
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;
use trc::{ClusterEvent, ServerEvent};

pub fn spawn_broadcast_subscriber(inner: Arc<Inner>, mut shutdown_rx: watch::Receiver<bool>) {
    let this_node_id = {
        let _core = inner.shared_core.load();
        if _core.storage.coordinator.is_none() || _core.storage.registry.is_recovery_mode() {
            return;
        }
        _core.network.node_id as u16
    };

    tokio::spawn(async move {
        let mut retry_count: u32 = 0;
        // inbuxa: whether events may have been published while this node
        // had no subscription
        let mut lost_events = false;

        trc::event!(Cluster(ClusterEvent::SubscriberStart));

        'subscribe: loop {
            let coordinator = inner.shared_core.load().storage.coordinator.clone();
            if coordinator.is_none() {
                trc::event!(
                    Cluster(ClusterEvent::SubscriberError),
                    Details = "Coordinator is no longer configured"
                );
                break;
            }

            let mut stream = match coordinator.subscribe(BROADCAST_TOPIC).await {
                Ok(stream) => {
                    retry_count = 0;
                    if std::mem::take(&mut lost_events) {
                        recover_missed_events(&inner, "Subscribed again").await;
                    }
                    stream
                }
                Err(err) => {
                    trc::event!(
                        Cluster(ClusterEvent::SubscriberError),
                        CausedBy = err,
                        Details = "Failed to subscribe to channel"
                    );

                    match tokio::time::timeout(
                        subscribe_retry_delay(retry_count),
                        shutdown_rx.changed(),
                    )
                    .await
                    {
                        Ok(_) => {
                            break;
                        }
                        Err(_) => {
                            retry_count = retry_count.saturating_add(1);
                            continue;
                        }
                    }
                }
            };

            // inbuxa: the client subscribes again by itself after a
            // reconnection, but core NATS delivers at most once, so what the
            // cluster published meanwhile never arrives
            let mut reconnects = coordinator.reconnects();
            if let Some(reconnects) = &mut reconnects {
                reconnects.mark_unchanged();
            }

            loop {
                tokio::select! {
                    changed = async {
                        match &mut reconnects {
                            Some(reconnects) => reconnects.changed().await.is_ok(),
                            None => std::future::pending().await,
                        }
                    } => {
                        if changed {
                            recover_missed_events(&inner, "Reconnected to the coordinator").await;
                        } else {
                            reconnects = None;
                        }
                    },
                    message = stream.next() => {
                        match message {
                            Some(message) => {
                                let mut batch = BroadcastBatch::new(message.payload().iter());
                                let node_id = match batch.node_id() {
                                    Some(node_id) => {
                                        if node_id != this_node_id {
                                            node_id
                                        } else {
                                            trc::event!(
                                                Cluster(ClusterEvent::MessageSkipped),
                                                Details = message.payload()
                                            );
                                            continue;
                                        }
                                    }
                                    None => {
                                        trc::event!(
                                            Cluster(ClusterEvent::MessageInvalid),
                                            Details = message.payload()
                                        );
                                        continue;
                                    }
                                };

                                inner
                                    .shared_core
                                    .load()
                                    .storage
                                    .data
                                    .invalidate_read_snapshot();

                                loop {
                                    match batch.next_event() {
                                        Ok(Some(event)) => {
                                            trc::event!(
                                                Cluster(ClusterEvent::MessageReceived),
                                                From = node_id,
                                                To = this_node_id,
                                                Details = log_event(&event),
                                            );
                                            match event {
                                                BroadcastEvent::PushNotification(notification) => {
                                                    // inbuxa: ST-7: another node's change raises this
                                                    // node's high-water mark for the account
                                                    match &notification {
                                                        common::ipc::PushNotification::StateChange(change) => inner
                                                            .build_server()
                                                            .core
                                                            .storage
                                                            .data
                                                            .note_change(change.account_id, change.change_id),
                                                        common::ipc::PushNotification::EmailPush(push) => inner
                                                            .build_server()
                                                            .core
                                                            .storage
                                                            .data
                                                            .note_change(push.account_id, push.change_id),
                                                        _ => {}
                                                    }
                                                    if inner
                                                        .ipc
                                                        .push_tx
                                                        .send(PushEvent::Publish {
                                                            notification,
                                                            broadcast: false,
                                                        })
                                                        .await
                                                        .is_err()
                                                    {
                                                        trc::event!(
                                                            Server(ServerEvent::ThreadError),
                                                            Details = "Error sending push notification.",
                                                            CausedBy = trc::location!()
                                                        );
                                                    }
                                                }
                                                BroadcastEvent::PushServerUpdate(account_id) => {
                                                    if inner
                                                        .ipc
                                                        .push_tx
                                                        .send(PushEvent::PushServerUpdate { account_id, broadcast: false })
                                                        .await
                                                        .is_err()
                                                    {
                                                        trc::event!(
                                                            Server(ServerEvent::ThreadError),
                                                            Details = "Error sending reload request.",
                                                            CausedBy = trc::location!()
                                                        );
                                                    }
                                                }
                                                BroadcastEvent::CacheInvalidate(changes) => {
                                                    inner.build_server().invalidate_local_caches(&changes).await;

                                                }
                                                BroadcastEvent::CacheInvalidateAll => {
                                                    inner.build_server().invalidate_all_local_caches();
                                                }
                                                BroadcastEvent::CacheInvalidateNegative => {
                                                    inner.build_server().invalidate_all_local_negative_caches();
                                                }
                                                BroadcastEvent::MtaQueueStatus { is_running } => {
                                                    let _ = inner
                                                            .ipc
                                                            .queue_tx
                                                            .send(QueueEvent::Paused(!is_running))
                                                            .await;
                                                }
                                                // inbuxa: AL-3: sessions an account has
                                                // open here end too
                                                BroadcastEvent::EndSessions(account_id) => {
                                                    let _ = inner
                                                        .ipc
                                                        .push_tx
                                                        .send(PushEvent::Revoke { account_id })
                                                        .await;
                                                }
                                                // inbuxa: DL-15: this node checks
                                                // itself too
                                                BroadcastEvent::DeliverabilityCheck => {
                                                    crate::inbuxa_deliverability::CHECK_NOW
                                                        .notify_one();
                                                }
                                                BroadcastEvent::QueueRefresh => {
                                                    if inner.shared_core.load().network.roles.outbound_mta {
                                                        let _ = inner
                                                                .ipc
                                                                .queue_tx
                                                                .send(QueueEvent::Refresh)
                                                                .await;
                                                    }
                                                }
                                                BroadcastEvent::RegistryChange(change) => {
                                                    match Box::pin(inner.build_server().reload_registry(change)).await {
                                                        Ok(result) => {
                                                            result.log();
                                                        }
                                                        Err(err) => {
                                                            trc::error!(
                                                                err.details("Failed to reload settings")
                                                                    .caused_by(trc::location!())
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Ok(None) => break,
                                        Err(_) => {
                                            trc::event!(
                                                Cluster(ClusterEvent::MessageInvalid),
                                                Details = message.payload()
                                            );
                                            break;
                                        }
                                    }
                                }
                            }
                            None => {
                                trc::event!(
                                    Cluster(ClusterEvent::SubscriberDisconnected),
                                );
                                lost_events = true;
                                break;
                            }
                        }
                    },
                    _ = shutdown_rx.changed() => {
                        break 'subscribe;
                    }
                };
            }
        }

        trc::event!(Cluster(ClusterEvent::SubscriberStop));
    });
}

/// inbuxa: after a gap in which cluster events may have been missed, drops
/// every local cache that only those events keep fresh and rebuilds the
/// settings, certificates and blocked addresses from the registry, as the
/// missed events would have. The message caches check the change log on
/// each use and need nothing.
async fn recover_missed_events(inner: &Arc<Inner>, why: &str) {
    let server = inner.build_server();
    server.invalidate_all_local_caches();
    for object in [
        ObjectType::ClusterRole,
        ObjectType::Certificate,
        ObjectType::BlockedIp,
    ] {
        match Box::pin(server.reload_registry(RegistryChange::Reload(object))).await {
            Ok(result) => result.log(),
            Err(err) => {
                trc::error!(
                    err.details("Failed to reload settings after the coordinator came back")
                        .caused_by(trc::location!())
                );
            }
        }
    }
    trc::event!(
        Cluster(ClusterEvent::CoordinatorConnected),
        Details = format!(
            "{why}: events may have been missed; local caches dropped and settings reloaded"
        ),
    );
}

/// Delay before the next subscribe attempt: 1 s, 2 s, 4 s ... capped at 64 s.
fn subscribe_retry_delay(retry_count: u32) -> Duration {
    Duration::from_secs(1u64 << retry_count.min(6))
}

fn log_event(event: &BroadcastEvent) -> trc::Value {
    match event {
        BroadcastEvent::PushNotification(notification) => match notification {
            PushNotification::StateChange(state_change) => trc::Value::Array(vec![
                "StateChange".into(),
                state_change.account_id.into(),
                state_change.change_id.into(),
                (*state_change.types.as_ref()).into(),
            ]),
            PushNotification::CalendarAlert(calendar_alert) => trc::Value::Array(vec![
                "CalendarAlert".into(),
                calendar_alert.account_id.into(),
                calendar_alert.event_id.into(),
                calendar_alert.recurrence_id.into(),
                calendar_alert.uid.clone().into(),
                calendar_alert.alert_id.clone().into(),
            ]),
            PushNotification::EmailPush(email_push) => trc::Value::Array(vec![
                "EmailPush".into(),
                email_push.account_id.into(),
                email_push.email_id.into(),
                email_push.change_id.into(),
            ]),
        },
        BroadcastEvent::PushServerUpdate(account_id) => {
            trc::Value::Array(vec!["PushServerUpdate".into(), (*account_id).into()])
        }
        BroadcastEvent::EndSessions(account_id) => {
            trc::Value::Array(vec!["EndSessions".into(), (*account_id).into()])
        }
        BroadcastEvent::DeliverabilityCheck => "DeliverabilityCheck".into(),
        BroadcastEvent::RegistryChange(change) => match change {
            RegistryChange::Insert(id) => trc::Value::Array(vec![
                "RegistryInsert".into(),
                id.object().as_str().into(),
                id.id().id().into(),
            ]),
            RegistryChange::Delete(id) => trc::Value::Array(vec![
                "RegistryDelete".into(),
                id.object().as_str().into(),
                id.id().id().into(),
            ]),
            RegistryChange::Reload(object) => {
                trc::Value::Array(vec!["RegistryReload".into(), object.as_str().into()])
            }
        },
        BroadcastEvent::CacheInvalidate(items) => {
            let mut array = Vec::with_capacity(items.len() + 1);
            array.push("CacheInvalidation".into());
            for item in items {
                array.push(format!("{:?}", item).into());
            }
            trc::Value::Array(array)
        }
        BroadcastEvent::CacheInvalidateAll => "CacheInvalidateAll".into(),
        BroadcastEvent::CacheInvalidateNegative => "CacheInvalidateNegative".into(),
        BroadcastEvent::MtaQueueStatus { is_running } => {
            if *is_running {
                "MtaQueueRunning".into()
            } else {
                "MtaQueuePaused".into()
            }
        }
        BroadcastEvent::QueueRefresh => "QueueRefresh".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::subscribe_retry_delay;
    use std::time::Duration;

    #[test]
    fn subscribe_retry_backoff_grows_then_caps() {
        let schedule: Vec<u64> = (0..10)
            .map(|n| subscribe_retry_delay(n).as_secs())
            .collect();
        assert_eq!(schedule, vec![1, 2, 4, 8, 16, 32, 64, 64, 64, 64]);
        // No shift overflow at the top of the range.
        assert_eq!(subscribe_retry_delay(u32::MAX), Duration::from_secs(64));
    }
}
