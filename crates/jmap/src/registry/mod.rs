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
    // inbuxa: every Enterprise feature is rebuilt (docs/spec/SPEC.md §4), the
    // last being monitoring (MON-39), so nothing is refused here any more
    fn assert_enterprise_object(&self, _: ObjectType) -> trc::Result<()> {
        Ok(())
    }
}
