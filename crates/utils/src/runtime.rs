/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    future::Future,
    io::{self, Write},
    mem,
};
use tokio::runtime::{Builder, Runtime};

pub fn run_server<F: Future>(future: F) -> io::Result<F::Output> {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let output = runtime.block_on(future);
    finish(runtime);
    Ok(output)
}

pub fn finish(runtime: Runtime) {
    mem::forget(runtime);
}

pub fn exit(code: i32) -> ! {
    let _ = io::stdout().flush();
    unsafe { libc::_exit(code) }
}
