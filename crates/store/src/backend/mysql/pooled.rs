/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::into_error;
use futures::FutureExt;
use mysql_async::Conn;
use std::ops::{Deref, DerefMut};

pub(super) struct PooledConn {
    conn: Option<Conn>,
    detach: bool,
}

impl PooledConn {
    pub(super) fn new(conn: Conn) -> Self {
        PooledConn {
            conn: Some(conn),
            detach: false,
        }
    }

    pub(super) fn end_transaction(
        &mut self,
        result: Result<(), mysql_async::Error>,
    ) -> trc::Result<()> {
        result.map_err(|err| {
            self.detach = true;
            into_error(err)
        })
    }
}

impl Deref for PooledConn {
    type Target = Conn;

    #[inline]
    fn deref(&self) -> &Conn {
        self.conn
            .as_ref()
            .expect("the connection is only taken when the guard is dropped")
    }
}

impl DerefMut for PooledConn {
    #[inline]
    fn deref_mut(&mut self) -> &mut Conn {
        self.conn
            .as_mut()
            .expect("the connection is only taken when the guard is dropped")
    }
}

impl Drop for PooledConn {
    fn drop(&mut self) {
        if self.detach
            && let Some(conn) = self.conn.take()
        {
            drop(conn.disconnect().now_or_never());
        }
    }
}
