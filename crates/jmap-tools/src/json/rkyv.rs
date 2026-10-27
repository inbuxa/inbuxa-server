/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Element, Property, Value};
use rkyv::{
    option::ArchivedOption,
    primitive::{ArchivedU32, ArchivedU64},
    string::ArchivedString,
};

impl<'ctx, P: Property, E: Element, T> From<&ArchivedOption<T>> for Value<'ctx, P, E>
where
    for<'x> &'x T: Into<Value<'ctx, P, E>>,
{
    fn from(value: &ArchivedOption<T>) -> Self {
        match value {
            ArchivedOption::Some(value) => value.into(),
            ArchivedOption::None => Value::Null,
        }
    }
}

impl<'ctx, P: Property, E: Element> From<&ArchivedString> for Value<'ctx, P, E> {
    fn from(value: &ArchivedString) -> Self {
        Value::Str(value.to_string().into())
    }
}

impl<'ctx, P: Property, E: Element> From<&ArchivedU32> for Value<'ctx, P, E> {
    fn from(value: &ArchivedU32) -> Self {
        Value::Number(u32::from(value).into())
    }
}

impl<'ctx, P: Property, E: Element> From<&ArchivedU64> for Value<'ctx, P, E> {
    fn from(value: &ArchivedU64) -> Self {
        Value::Number(u64::from(value).into())
    }
}
