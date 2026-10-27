/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Event, push::spawn_push_manager};
use common::{
    Inner,
    ipc::{BroadcastEvent, PushEvent},
};
use std::sync::Arc;
use tokio::sync::mpsc;
use trc::ServerEvent;

pub fn spawn_push_router(inner: Arc<Inner>, mut change_rx: mpsc::Receiver<PushEvent>) {
    let push_tx = spawn_push_manager(inner.clone());

    tokio::spawn(async move {
        while let Some(event) = change_rx.recv().await {
            match event {
                PushEvent::Stop => {
                    inner.ipc.push_subscribers.close_all();
                    if push_tx.send(Event::Reset).await.is_err() {
                        trc::event!(
                            Server(ServerEvent::ThreadError),
                            Details = "Error sending push reset.",
                            CausedBy = trc::location!()
                        );
                    }
                    break;
                }

                PushEvent::PushServerRegister { activate, expired } => {
                    inner
                        .ipc
                        .push_subscribers
                        .register_push(&activate, &expired);
                }

                PushEvent::Publish { notification } => {
                    if push_tx.send(Event::Push { notification }).await.is_err() {
                        trc::event!(
                            Server(ServerEvent::ThreadError),
                            Details = "Error sending push updates.",
                            CausedBy = trc::location!()
                        );
                    }
                }

                PushEvent::PushServerUpdate {
                    account_id,
                    broadcast,
                } => {
                    if broadcast
                        && let Some(broadcast_tx) = inner.ipc.broadcast_tx.as_ref()
                        && broadcast_tx
                            .send(BroadcastEvent::PushServerUpdate(account_id))
                            .await
                            .is_err()
                    {
                        trc::event!(
                            Server(trc::ServerEvent::ThreadError),
                            Details = "Error sending broadcast event.",
                            CausedBy = trc::location!()
                        );
                    }

                    if push_tx.send(Event::Update { account_id }).await.is_err() {
                        trc::event!(
                            Server(ServerEvent::ThreadError),
                            Details = "Error sending push updates.",
                            CausedBy = trc::location!()
                        );
                    }
                }
            }
        }
    });
}
