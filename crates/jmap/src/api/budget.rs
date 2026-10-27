/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */


use common::network::memory::{MEMORY_STEP, MemoryReservation, ReservationScope};
use std::mem::take;
use trc::AddContext;

pub const SERIALIZED_COPIES: u64 = 3;
pub const ARCHIVE_EXPANSION: u64 = 2;
const LIGHT_REQUEST_BYTES: u64 = 16 * MEMORY_STEP;

pub struct GetBudget<'x> {
    scope: ReservationScope<'x>,
    estimate: u64,
    light: u64,
}

impl<'x> GetBudget<'x> {
    pub fn new(reservation: &'x mut MemoryReservation) -> Self {
        GetBudget {
            scope: reservation.scope(),
            estimate: 0,
            light: 0,
        }
    }

    pub fn add(&mut self, bytes: u64) -> trc::Result<()> {
        self.estimate = self
            .estimate
            .saturating_add(bytes.saturating_mul(SERIALIZED_COPIES));
        if self.estimate >= MEMORY_STEP {
            self.scope
                .try_reserve_extra(self.estimate)
                .caused_by(trc::location!())
        } else {
            Ok(())
        }
    }

    pub fn add_light(&mut self, bytes: u64) -> trc::Result<()> {
        self.light = self.light.saturating_add(bytes);
        if self.light >= LIGHT_REQUEST_BYTES {
            let light = take(&mut self.light);
            self.add(light)
        } else {
            Ok(())
        }
    }

    pub fn add_archive(&mut self, archive_bytes: usize, objects: usize) -> trc::Result<()> {
        self.add(
            (archive_bytes as u64)
                .saturating_mul(objects as u64)
                .saturating_mul(ARCHIVE_EXPANSION),
        )
    }

    pub fn commit(self) {
        self.scope.commit();
    }
}
