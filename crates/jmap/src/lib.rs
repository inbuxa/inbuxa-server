/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

// inbuxa: composite stores (sharded members, read replicas) nest store
// futures deeply enough to pass rustc's default query depth
#![recursion_limit = "512"]

#![warn(clippy::large_futures)]

use jmap_proto::object::JmapObjectId;
use jmap_tools::{Element, Property, Value};
use std::str::FromStr;
use types::id::Id;

pub(crate) fn matches_id<P: Property, E: Element + JmapObjectId>(
    value: &Value<'_, P, E>,
    id: Id,
) -> bool {
    match value {
        Value::Element(element) => element.as_id() == Some(id),
        Value::Str(value) => Id::from_str(value.as_ref()).is_ok_and(|value| value == id),
        _ => false,
    }
}

pub mod addressbook;
pub mod api;
pub mod blob;
pub mod calendar;
pub mod calendar_event;
pub mod calendar_event_notification;
pub mod changes;
pub mod contact;
pub mod email;
pub mod file;
pub mod identity;
pub mod inbuxa; // inbuxa: the fork's own features
pub mod mailbox;
pub mod participant_identity;
pub mod principal;
pub mod push;
pub mod quota;
pub mod registry;
pub mod share_notification;
pub mod sieve;
pub mod submission;
pub mod thread;
pub mod vacation;
pub mod websocket;
