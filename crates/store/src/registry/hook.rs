/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: told of every registry write that succeeded, with the object as
//! it was and as it is, so the audit log records what the server changed on
//! its own (audit-hold-lock spec, AU-1.10). The store knows nothing of the
//! audit log; the server installs the hook once it has one.

use registry::schema::prelude::{Object, ObjectType};
use std::{future::Future, pin::Pin, sync::Arc};
use types::id::Id;

/// One registry write that succeeded.
pub struct RegistryChange<'a> {
    pub object_type: ObjectType,
    pub id: Id,
    /// Absent for an insert.
    pub before: Option<&'a Object>,
    /// Absent for a delete.
    pub after: Option<&'a Object>,
}

pub trait RegistryWriteHook: Send + Sync {
    fn written<'a>(
        &'a self,
        change: RegistryChange<'a>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

pub type RegistryHookSlot = Arc<std::sync::OnceLock<Arc<dyn RegistryWriteHook>>>;
