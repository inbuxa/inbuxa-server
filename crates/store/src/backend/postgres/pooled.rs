/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{into_error, pool::PgObject};
use deadpool::managed::Object;
use std::ops::{Deref, DerefMut};

pub(super) struct PooledConn {
    object: Option<PgObject>,
    on_drop: OnDrop,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OnDrop {
    Return,
    RollBack,
    Detach,
}

impl PooledConn {
    pub(super) fn new(object: PgObject) -> Self {
        PooledConn {
            object: Some(object),
            on_drop: OnDrop::Return,
        }
    }

    #[inline]
    pub(super) fn set_detach(&mut self, detach: bool) {
        self.on_drop = if detach {
            OnDrop::Detach
        } else {
            OnDrop::Return
        };
    }

    #[inline]
    pub(super) fn transaction_started(&mut self) {
        self.on_drop = OnDrop::RollBack;
    }

    pub(super) fn abandon_transaction(&mut self) {
        self.on_drop = if self.defer_rollback() {
            OnDrop::Return
        } else {
            OnDrop::Detach
        };
    }

    pub(super) fn end_transaction(
        &mut self,
        result: Result<(), tokio_postgres::Error>,
    ) -> trc::Result<()> {
        match result {
            Ok(()) => {
                self.on_drop = OnDrop::Return;
                Ok(())
            }
            Err(err) => {
                self.on_drop = OnDrop::Detach;
                Err(into_error(err))
            }
        }
    }
}

impl Deref for PooledConn {
    type Target = PgObject;

    #[inline]
    fn deref(&self) -> &PgObject {
        self.object
            .as_ref()
            .expect("the connection is only taken when the guard is dropped")
    }
}

impl DerefMut for PooledConn {
    #[inline]
    fn deref_mut(&mut self) -> &mut PgObject {
        self.object
            .as_mut()
            .expect("the connection is only taken when the guard is dropped")
    }
}

impl Drop for PooledConn {
    fn drop(&mut self) {
        if self.on_drop == OnDrop::RollBack && self.object.is_some() {
            self.abandon_transaction();
        }
        if self.on_drop == OnDrop::Detach
            && let Some(object) = self.object.take()
        {
            drop(Object::take(object));
        }
    }
}
