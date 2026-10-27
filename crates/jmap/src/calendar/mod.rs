/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use groupware::calendar::availability::AvailabilityPreference;
use jmap_proto::object::calendar::IncludeInAvailability;

pub mod get;
pub mod set;

pub(crate) trait Availability: Sized {
    fn from_flags(flags: u16) -> Option<Self>;
}

impl Availability for IncludeInAvailability {
    fn from_flags(flags: u16) -> Option<Self> {
        AvailabilityPreference::from_flags(flags).map(|preference| match preference {
            AvailabilityPreference::All => IncludeInAvailability::All,
            AvailabilityPreference::Attending => IncludeInAvailability::Attending,
            AvailabilityPreference::None => IncludeInAvailability::None,
        })
    }
}
