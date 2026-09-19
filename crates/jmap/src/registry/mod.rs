/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use registry::schema::prelude::ObjectType;

pub mod get;
pub mod mapping;
pub mod query;
pub mod set;

pub trait EnterpriseRegistry {
    fn assert_enterprise_object(&self, object_type: ObjectType) -> trc::Result<()>;
}

impl EnterpriseRegistry for Server {
    fn assert_enterprise_object(&self, object_type: ObjectType) -> trc::Result<()> {
        if !matches!(
            object_type,
            ObjectType::Metric
                | ObjectType::Trace
        ) {
            return Ok(());
        }


        // These are the Enterprise features INBUXA hasn't rebuilt yet
        // (docs/spec/SPEC.md §4). Each type leaves this list when its rebuild
        // lands. There's no edition to upgrade to, so the message says so.
        Err(trc::JmapEvent::Forbidden.into_err().details(concat!(
            "This feature isn't available in ",
            types::brand!(),
            " yet."
        )))
    }
}
