/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_builder::headers::message_id::generate_message_id_header;
#[cfg(not(all(test, stalwart_tests)))]
use mail_builder::mime;
use std::time::SystemTime;

#[inline(always)]
pub(crate) fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64
}

#[inline(always)]
#[cfg(not(all(test, stalwart_tests)))]
pub(crate) fn make_boundary() -> String {
    mime::make_boundary(".")
}

#[inline(always)]
pub(crate) fn write_message_id(output: &mut Vec<u8>, hostname: &str) {
    generate_message_id_header(output, hostname);
}
