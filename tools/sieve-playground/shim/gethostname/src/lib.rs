/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

use std::ffi::OsString;

pub fn gethostname() -> OsString {
    OsString::from("localhost")
}
