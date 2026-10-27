/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{Element, Property, Value};

pub(crate) struct Elements<'a, 'x, P: Property, E: Element<Property = P>> {
    stack: Vec<&'a Value<'x, P, E>>,
}

impl<'a, 'x, P: Property, E: Element<Property = P>> Elements<'a, 'x, P, E> {
    pub(crate) fn new(value: &'a Value<'x, P, E>) -> Self {
        let mut stack = Vec::with_capacity(16);
        stack.push(value);
        Self { stack }
    }

    pub(crate) fn from_values(values: impl Iterator<Item = &'a Value<'x, P, E>>) -> Self {
        let mut stack = Vec::with_capacity(16);
        stack.extend(values);
        Self { stack }
    }
}

impl<'a, 'x, P: Property, E: Element<Property = P>> Iterator for Elements<'a, 'x, P, E> {
    type Item = &'a E;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(value) = self.stack.pop() {
            match value {
                Value::Element(element) => return Some(element),
                Value::Array(items) => self.stack.extend(items.iter().rev()),
                Value::Object(obj) => self.stack.extend(obj.as_vec().iter().rev().map(|(_, v)| v)),
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::Str(_) => {}
            }
        }

        None
    }
}
