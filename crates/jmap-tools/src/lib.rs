/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
#![deny(rust_2018_idioms)]
#![forbid(unsafe_code)]

mod json;
mod pointer;

pub use json::key::Key;
pub use json::object_vec::{ObjectAsVec, ObjectAsVec as Map};
pub use json::value::{Element, Null, Property, Value};
pub use pointer::{
    JsonPointer, JsonPointerHandler, JsonPointerItem, JsonPointerIter, PointerDepth,
};
