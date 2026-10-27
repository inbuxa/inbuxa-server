/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{JsonPointerHandler, JsonPointerItem, NumberKey};
use crate::json::key::Key;
use crate::pointer::JsonPointerIter;
use crate::{Element, ObjectAsVec, Property, Value};
use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::BuildHasher;

impl<'x, P: Property, E: Element> JsonPointerHandler<'x, P, E> for Value<'x, P, E> {
    fn eval_jptr<'y>(
        &'y self,
        mut pointer: JsonPointerIter<'_, P>,
        results: &mut Vec<Cow<'y, Value<'x, P, E>>>,
    ) {
        match pointer.next() {
            Some(JsonPointerItem::Key(key)) => {
                if let Value::Object(map) = self
                    && let Some(v) = map.get(key)
                {
                    v.eval_jptr(pointer, results);
                }
            }
            Some(JsonPointerItem::Number(n)) => match self {
                Value::Array(values) => {
                    if let Some(v) = usize::try_from(*n).ok().and_then(|index| values.get(index)) {
                        v.eval_jptr(pointer, results);
                    }
                }
                Value::Object(map) => {
                    let mut buf = NumberKey::default();
                    if let Some(v) = map.get(&Key::Borrowed(buf.format(*n))) {
                        v.eval_jptr(pointer, results);
                    }
                }
                _ => {}
            },
            Some(JsonPointerItem::Wildcard) => match self {
                Value::Array(values) => {
                    for v in values {
                        v.eval_jptr(pointer.clone(), results);
                    }
                }
                Value::Object(map) => {
                    for v in map.values() {
                        v.eval_jptr(pointer.clone(), results);
                    }
                }
                _ => {}
            },
            Some(JsonPointerItem::Invalid(_)) => {}
            Some(JsonPointerItem::Root) | None => {
                results.push(Cow::Borrowed(self));
            }
        }
    }

    fn patch_jptr<'y: 'x>(
        &mut self,
        mut pointer: JsonPointerIter<'_, P>,
        value: Value<'y, P, E>,
    ) -> bool {
        match pointer.next() {
            Some(JsonPointerItem::Key(key)) => {
                if let Value::Object(map) = self {
                    return map.patch_entry(key, || key.clone(), pointer, value);
                }
            }
            Some(JsonPointerItem::Number(n)) => match self {
                Value::Array(values) => {
                    if let Some(item) = usize::try_from(*n)
                        .ok()
                        .and_then(|index| values.get_mut(index))
                    {
                        return match (pointer.peek().is_some(), value) {
                            (true, value) => item.patch_jptr(pointer, value),
                            (false, Value::Null) => false,
                            (false, value) => {
                                *item = value;
                                true
                            }
                        };
                    }
                }
                Value::Object(map) => {
                    let mut buf = NumberKey::default();
                    let digits = buf.format(*n);
                    return map.patch_entry(
                        &Key::Borrowed(digits),
                        || Key::Owned(digits.to_string()),
                        pointer,
                        value,
                    );
                }
                _ => {}
            },
            Some(
                JsonPointerItem::Wildcard | JsonPointerItem::Root | JsonPointerItem::Invalid(_),
            )
            | None => (),
        }

        false
    }

    fn to_value<'y>(&'y self) -> Cow<'y, Value<'x, P, E>> {
        Cow::Borrowed(self)
    }
}

impl<'x, P: Property, E: Element> ObjectAsVec<'x, P, E> {
    fn patch_entry<'y: 'x>(
        &mut self,
        key: &Key<'_, P>,
        new_key: impl FnOnce() -> Key<'static, P>,
        mut pointer: JsonPointerIter<'_, P>,
        value: Value<'y, P, E>,
    ) -> bool {
        let Some(pos) = self.position(key) else {
            return match (pointer.peek().is_none(), value) {
                (false, _) => false,
                (true, Value::Null) => true,
                (true, value) => {
                    self.insert_unchecked(new_key(), value);
                    true
                }
            };
        };

        if pointer.peek().is_some() {
            self.0
                .get_mut(pos)
                .is_some_and(|(_, item)| item.patch_jptr(pointer, value))
        } else if matches!(value, Value::Null) {
            self.0.remove(pos);
            true
        } else if let Some((_, item)) = self.0.get_mut(pos) {
            *item = value;
            true
        } else {
            false
        }
    }
}

impl<'x, P: Property, E: Element, T> JsonPointerHandler<'x, P, E> for Vec<T>
where
    T: JsonPointerHandler<'x, P, E> + for<'y> TryFrom<Value<'y, P, E>> + 'static,
{
    fn eval_jptr<'y>(
        &'y self,
        mut pointer: JsonPointerIter<'_, P>,
        results: &mut Vec<Cow<'y, Value<'x, P, E>>>,
    ) {
        match pointer.next() {
            Some(JsonPointerItem::Number(n)) => {
                if let Some(v) = usize::try_from(*n).ok().and_then(|index| self.get(index)) {
                    v.eval_jptr(pointer, results);
                }
            }
            Some(JsonPointerItem::Wildcard) => {
                for v in self {
                    v.eval_jptr(pointer.clone(), results);
                }
            }
            Some(JsonPointerItem::Root) | None => {
                results.push(self.to_value());
            }
            _ => {}
        }
    }

    fn patch_jptr<'y: 'x>(
        &mut self,
        mut pointer: JsonPointerIter<'_, P>,
        value: Value<'y, P, E>,
    ) -> bool {
        if let Some(JsonPointerItem::Number(n)) = pointer.next()
            && let Some(item) = usize::try_from(*n)
                .ok()
                .and_then(|index| self.get_mut(index))
        {
            if pointer.peek().is_some() {
                return item.patch_jptr(pointer, value);
            } else if !matches!(value, Value::Null)
                && let Ok(value) = T::try_from(value)
            {
                *item = value;
                return true;
            }
        }
        false
    }

    fn to_value<'y>(&'y self) -> Cow<'y, Value<'x, P, E>> {
        Cow::Owned(Value::Array(
            self.iter().map(|v| v.to_value().into_owned()).collect(),
        ))
    }
}

impl<'x, P: Property, E: Element, T> TryFrom<Value<'x, P, E>> for Vec<T>
where
    T: JsonPointerHandler<'x, P, E> + for<'y> TryFrom<Value<'y, P, E>> + 'static,
{
    type Error = ();

    fn try_from(value: Value<'x, P, E>) -> Result<Self, Self::Error> {
        if let Value::Array(arr) = value {
            arr.into_iter()
                .map(T::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ())
        } else {
            Err(())
        }
    }
}

impl<'x, P: Property, E: Element, T, S: BuildHasher + Default> JsonPointerHandler<'x, P, E>
    for HashMap<String, T, S>
where
    T: JsonPointerHandler<'x, P, E> + for<'y> TryFrom<Value<'y, P, E>> + 'static,
{
    fn eval_jptr<'y>(
        &'y self,
        mut pointer: JsonPointerIter<'_, P>,
        results: &mut Vec<Cow<'y, Value<'x, P, E>>>,
    ) {
        match pointer.next() {
            Some(JsonPointerItem::Key(key)) => {
                if let Some(v) = self.get(key.to_string().as_ref()) {
                    v.eval_jptr(pointer, results);
                }
            }
            Some(JsonPointerItem::Number(n)) => {
                let mut buf = NumberKey::default();
                if let Some(v) = self.get(buf.format(*n)) {
                    v.eval_jptr(pointer, results);
                }
            }
            Some(JsonPointerItem::Wildcard) => {
                for v in self.values() {
                    v.eval_jptr(pointer.clone(), results);
                }
            }
            Some(JsonPointerItem::Invalid(_)) => {}
            Some(JsonPointerItem::Root) | None => {
                results.push(self.to_value());
            }
        }
    }

    fn patch_jptr<'y: 'x>(
        &mut self,
        mut pointer: JsonPointerIter<'_, P>,
        value: Value<'y, P, E>,
    ) -> bool {
        let mut buf = NumberKey::default();
        let key = match pointer.next() {
            Some(JsonPointerItem::Key(key)) => key.to_string(),
            Some(JsonPointerItem::Number(n)) => Cow::Borrowed(buf.format(*n)),
            Some(
                JsonPointerItem::Wildcard | JsonPointerItem::Root | JsonPointerItem::Invalid(_),
            )
            | None => return false,
        };

        if pointer.peek().is_some() {
            self.get_mut(key.as_ref())
                .is_some_and(|item| item.patch_jptr(pointer, value))
        } else if matches!(value, Value::Null) {
            self.remove(key.as_ref());
            true
        } else if let Ok(value) = T::try_from(value) {
            if let Some(item) = self.get_mut(key.as_ref()) {
                *item = value;
            } else {
                self.insert(key.into_owned(), value);
            }
            true
        } else {
            false
        }
    }

    fn to_value<'y>(&'y self) -> Cow<'y, Value<'x, P, E>> {
        Cow::Owned(Value::Object(
            self.iter()
                .map(|(k, v)| (Key::Owned(k.to_string()), v.to_value().into_owned()))
                .collect(),
        ))
    }
}

impl<'x, P: Property, E: Element, T> TryFrom<Value<'x, P, E>> for HashMap<String, T>
where
    T: JsonPointerHandler<'x, P, E> + for<'y> TryFrom<Value<'y, P, E>> + 'static,
{
    type Error = ();

    fn try_from(value: Value<'x, P, E>) -> Result<Self, Self::Error> {
        if let Value::Object(map) = value {
            map.into_vec()
                .into_iter()
                .map(|(k, v)| T::try_from(v).map(|v| (k.to_string().into_owned(), v)))
                .collect::<Result<HashMap<_, _>, _>>()
                .map_err(|_| ())
        } else {
            Err(())
        }
    }
}

