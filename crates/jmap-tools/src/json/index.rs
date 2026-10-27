/*
 * SPDX-FileCopyrightText: 2021 Pascal Seitz <pascal.seitz@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::{
    Value,
    json::value::{Element, Property},
};

/// A type that can be used to index into a `jmap_tools::Value`.
pub trait Index<'v, P: Property, E: Element> {
    /// Return None if the key is not already in the array or object.
    #[doc(hidden)]
    fn index_into(self, v: &'v Value<'v, P, E>) -> Option<&'v Value<'v, P, E>>;
}

impl<'v, P: Property, E: Element> Index<'v, P, E> for usize {
    #[inline]
    fn index_into(self, v: &'v Value<'v, P, E>) -> Option<&'v Value<'v, P, E>> {
        match v {
            Value::Array(vec) => vec.get(self),
            _ => None,
        }
    }
}

impl<'v, 'a: 'v, P: Property, E: Element> Index<'v, P, E> for &'a str {
    #[inline]
    fn index_into(self, v: &'v Value<'v, P, E>) -> Option<&'v Value<'v, P, E>> {
        match v {
            Value::Object(map) => map.iter().find(|(k, _v)| *k == &self).map(|(_k, v)| v),
            _ => None,
        }
    }
}
