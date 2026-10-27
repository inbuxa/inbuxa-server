/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Inner, Server,
    auth::AccessToken,
    ipc::{BroadcastEvent, PushEvent, PushNotification, subscribers::PushReceiver},
};
use store::write::{QueueNotify, TaskTypes};
use types::type_state::DataType;
use utils::map::bitmap::Bitmap;

impl Server {
    pub fn subscribe_push_manager(
        &self,
        access_token: &AccessToken,
        types: Bitmap<DataType>,
    ) -> PushReceiver {
        self.inner
            .ipc
            .push_subscribers
            .subscribe(access_token.member_ids(), types)
    }

    #[inline(always)]
    pub fn notify_task_queue(&self) {
        self.inner.ipc.task_tx.notify(TaskTypes::ALL);
    }

    #[inline(always)]
    pub fn notify_task_types(&self, task_types: TaskTypes) {
        self.inner.ipc.task_tx.notify(task_types);
    }

    #[inline(always)]
    pub fn notify_index_queue(&self) {
        self.inner.ipc.index_tx.notify_one();
    }

    pub async fn notify_queues(&self, queues: QueueNotify) {
        if !queues.task_types.is_empty() {
            self.notify_task_types(queues.task_types);
            self.cluster_broadcast(BroadcastEvent::TaskQueueRefresh(queues.task_types))
                .await;
        }

        if queues.search_index {
            self.notify_index_queue();
            self.cluster_broadcast(BroadcastEvent::IndexQueueRefresh)
                .await;
        }
    }

    pub async fn broadcast_push_notification(&self, notification: PushNotification) -> bool {
        let Some(broadcast_tx) = &self.inner.ipc.broadcast_tx else {
            return self.inner.publish_push_notification(notification).await;
        };
        let is_published = self
            .inner
            .publish_push_notification(notification.clone())
            .await;
        if broadcast_tx
            .send(BroadcastEvent::PushNotification(notification))
            .await
            .is_err()
        {
            trc::event!(
                Server(trc::ServerEvent::ThreadError),
                Details = "Error sending broadcast event.",
                CausedBy = trc::location!()
            );
        }
        is_published
    }

    pub async fn cluster_broadcast(&self, event: BroadcastEvent) {
        if let Some(broadcast_tx) = &self.inner.ipc.broadcast_tx
            && broadcast_tx.send(event).await.is_err()
        {
            trc::event!(
                Server(trc::ServerEvent::ThreadError),
                Details = "Error sending broadcast event.",
                CausedBy = trc::location!()
            );
        }
    }
}

impl Inner {
    pub async fn publish_push_notification(&self, notification: PushNotification) -> bool {
        if !self.ipc.push_subscribers.dispatch(&notification)
            || self
                .ipc
                .push_tx
                .send(PushEvent::Publish { notification })
                .await
                .is_ok()
        {
            true
        } else {
            trc::event!(
                Server(trc::ServerEvent::ThreadError),
                Details = "Error sending state change.",
                CausedBy = trc::location!()
            );

            false
        }
    }
}
