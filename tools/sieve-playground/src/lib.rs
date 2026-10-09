/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

// inbuxa: built for wasm32-wasip1, not with wasm-bindgen: the server's
// sieve-rs and mail-builder read the clock, which only WASI gives a browser
// module (the worker's shim answers it, with the playground's current
// time). Calls go through one export, JSON in and JSON out.

// The server's function modules import http's Uri as hyper's.
extern crate http as hyper;

pub mod functions;
pub mod handler;
pub mod output;
pub mod run;
pub mod settings;
#[cfg(test)]
mod tests;

use serde::Serialize;
use serde_json::Value;

use crate::{run::Request, settings::Settings};

pub fn version() -> &'static str {
    env!("SIEVE_VERSION")
}

pub fn capabilities() -> Vec<String> {
    settings::all_capabilities()
        .map(|capability| capability.to_string())
        .collect()
}

/// Runs one operation: `version`, `capabilities`, `defaults`, `compile` or
/// `run`, the last two taking a Request.
pub fn call(op: &str, payload: &[u8]) -> Result<Value, String> {
    fn to_value(value: impl Serialize) -> Result<Value, String> {
        serde_json::to_value(value).map_err(|err| err.to_string())
    }
    fn request(payload: &[u8]) -> Result<Request, String> {
        serde_json::from_slice(payload).map_err(|err| format!("Invalid request: {err}"))
    }
    match op {
        "version" => to_value(version()),
        "capabilities" => to_value(capabilities()),
        "defaults" => to_value(Settings::default()),
        "compile" => to_value(request(payload)?.compile()),
        "run" => to_value(request(payload)?.run()),
        op => Err(format!("Unknown operation {op}")),
    }
}

#[cfg(target_family = "wasm")]
mod abi {
    use serde_json::json;

    #[link(wasm_import_module = "playground")]
    unsafe extern "C" {
        /// Hands the host a panic's message before the module traps.
        fn panicked(ptr: *const u8, len: usize);
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn playground_init() {
        std::panic::set_hook(Box::new(|info| {
            let message = info.to_string();
            unsafe { panicked(message.as_ptr(), message.len()) };
        }));
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn playground_alloc(len: usize) -> *mut u8 {
        Box::into_raw(vec![0u8; len].into_boxed_slice()).cast()
    }

    /// # Safety
    /// `ptr` and `len` come from playground_alloc or playground_call.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn playground_free(ptr: *mut u8, len: usize) {
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) });
    }

    /// Takes the operation name and the JSON payload, each from
    /// playground_alloc, frees both, and returns `{"ok": ...}` or
    /// `{"error": "..."}` as (pointer << 32 | length), for the host to free.
    ///
    /// # Safety
    /// The pointers and lengths come from playground_alloc.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn playground_call(
        op_ptr: *mut u8,
        op_len: usize,
        payload_ptr: *mut u8,
        payload_len: usize,
    ) -> u64 {
        let op = unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(op_ptr, op_len)) };
        let payload = unsafe {
            Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                payload_ptr,
                payload_len,
            ))
        };
        let reply = match super::call(&String::from_utf8_lossy(&op), &payload) {
            Ok(value) => json!({ "ok": value }),
            Err(error) => json!({ "error": error }),
        };
        let out = serde_json::to_vec(&reply)
            .unwrap_or_default()
            .into_boxed_slice();
        let len = out.len() as u64;
        let ptr = Box::into_raw(out).cast::<u8>() as usize as u64;
        (ptr << 32) | len
    }
}
