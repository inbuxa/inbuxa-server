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

    #[cfg(not(feature = "enterprise"))]
    fn assert_enterprise_object(&self, _object_type: ObjectType) -> trc::Result<()> {
        Ok(())
    }
}
