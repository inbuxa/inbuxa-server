use serde::{Serialize, Serializer};

use crate::json::index::Index;
use crate::json::key::Key;
use crate::json::num::{N, Number};
pub use crate::json::object_vec::ObjectAsVec;
use crate::json::parser::Parser;
use crate::pointer::PointerDepth;
use core::fmt;
use core::hash::{Hash, Hasher};
use std::borrow::Cow;
use std::fmt::{Debug, Display};
use std::str::FromStr;

/// Represents any valid JMAP value.
#[derive(Clone, Eq, PartialEq, Hash, Default)]
pub enum Value<'ctx, P: Property, E: Element> {
    #[default]
    Null,
    Bool(bool),
    Number(Number),
    Element(E),
    Str(Cow<'ctx, str>),
    Array(Vec<Value<'ctx, P, E>>),
    Object(ObjectAsVec<'ctx, P, E>),
}

pub trait Property: Debug + Clone + PartialEq + Eq + PartialOrd + Ord + Hash {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self>;
    fn to_cow(&self) -> Cow<'static, str>;

    fn try_parse_nested(key: Option<&Key<'_, Self>>, value: &str, _: PointerDepth) -> Option<Self> {
        Self::try_parse(key, value)
    }

    fn is_opaque(&self) -> bool {
        false
    }

    fn key_eq(&self, other: &Self) -> bool {
        self.to_cow() == other.to_cow()
    }

    fn key_eq_str(&self, other: &str) -> bool {
        self.to_cow() == other
    }

    fn key_hash<H: Hasher>(&self, state: &mut H) {
        self.to_cow().hash(state)
    }

    fn serialize_text<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_cow())
    }
}

pub trait Element: Clone + PartialEq + Eq + Hash + Debug + Sized {
    type Property: Property;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self>;
    fn to_cow(&self) -> Cow<'static, str>;

    fn serialize_text<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_cow())
    }
}

impl<'ctx, P: Property, E: Element<Property = P>> Value<'ctx, P, E> {
    pub fn new_object() -> Self {
        Value::Object(ObjectAsVec::from(Vec::new()))
    }

    pub fn new_boolean_set(set: impl IntoIterator<Item = (Key<'ctx, P>, bool)>) -> Self {
        let mut obj = Vec::new();
        for (key, value) in set {
            obj.push((key, value.into()));
        }
        Value::Object(obj.into())
    }

    pub fn parse_json(json: &'ctx str) -> Result<Self, String> {
        Parser::parse(json)
    }

    /// Returns a reference to the value corresponding to the key.
    #[inline]
    pub fn get<I: Index<'ctx, P, E>>(&'ctx self, index: I) -> &'ctx Value<'ctx, P, E> {
        index.index_into(self).unwrap_or(&Value::Null)
    }

    pub fn is_object_and_contains_key(&self, key: &Key<'_, P>) -> bool {
        match self {
            Value::Object(obj) => obj.contains_key(key),
            _ => false,
        }
    }

    pub fn is_object_and_contains_any_key(&self, keys: &[Key<'_, P>]) -> bool {
        match self {
            Value::Object(obj) => obj.contains_any_key(keys),
            _ => false,
        }
    }

    #[inline]
    pub fn as_object_and_get(&self, key: &Key<'_, P>) -> Option<&Value<'ctx, P, E>> {
        match self {
            Value::Object(obj) => obj.get(key),
            _ => None,
        }
    }

    /// Returns true if `Value` is Value::Null.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Returns true if `Value` is Value::Array.
    pub fn is_array(&self) -> bool {
        matches!(self, Value::Array(_))
    }

    /// Returns true if `Value` is Value::Object.
    pub fn is_object(&self) -> bool {
        matches!(self, Value::Object(_))
    }

    /// Returns true if `Value` is Value::Bool.
    pub fn is_bool(&self) -> bool {
        matches!(self, Value::Bool(_))
    }

    /// Returns true if `Value` is Value::Number.
    pub fn is_number(&self) -> bool {
        matches!(self, Value::Number(_))
    }

    /// Returns true if `Value` is Value::Str.
    pub fn is_string(&self) -> bool {
        matches!(self, Value::Str(_))
    }

    /// Returns true if the Value is an integer between i64::MIN and i64::MAX.
    /// For any Value on which is_i64 returns true, as_i64 is guaranteed to return the integer
    /// value.
    pub fn is_i64(&self) -> bool {
        match self {
            Value::Number(n) => n.is_i64(),
            _ => false,
        }
    }

    /// Returns true if the Value is an integer between zero and u64::MAX.
    /// For any Value on which is_u64 returns true, as_u64 is guaranteed to return the integer
    /// value.
    pub fn is_u64(&self) -> bool {
        match self {
            Value::Number(n) => n.is_u64(),
            _ => false,
        }
    }

    /// Returns true if the Value is a f64 number.
    pub fn is_f64(&self) -> bool {
        match self {
            Value::Number(n) => n.is_f64(),
            _ => false,
        }
    }

    /// If the Value is an Array, returns an iterator over the elements in the array.
    pub fn iter_array(&self) -> Option<impl Iterator<Item = &Value<'_, P, E>>> {
        match self {
            Value::Array(arr) => Some(arr.iter()),
            _ => None,
        }
    }

    /// If the Value is an Object, returns an iterator over the elements in the object.
    pub fn iter_object(&self) -> Option<impl Iterator<Item = (&Key<'_, P>, &Value<'_, P, E>)>> {
        match self {
            Value::Object(arr) => Some(arr.iter()),
            _ => None,
        }
    }

    /// If the Value is an Array, returns the associated Array. Returns None otherwise.
    pub fn as_array(&self) -> Option<&[Value<'ctx, P, E>]> {
        match self {
            Value::Array(arr) => Some(arr),
            _ => None,
        }
    }

    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Value<'ctx, P, E>>> {
        match self {
            Value::Array(arr) => Some(arr),
            _ => None,
        }
    }

    pub fn into_array(self) -> Option<Vec<Value<'ctx, P, E>>> {
        match self {
            Value::Array(arr) => Some(arr),
            _ => None,
        }
    }

    /// If the Value is an Object, returns the associated Object. Returns None otherwise.
    pub fn as_object(&self) -> Option<&ObjectAsVec<'ctx, P, E>> {
        match self {
            Value::Object(obj) => Some(obj),
            _ => None,
        }
    }

    pub fn as_element(&self) -> Option<&E> {
        match self {
            Value::Element(element) => Some(element),
            _ => None,
        }
    }

    pub fn as_object_mut(&mut self) -> Option<&mut ObjectAsVec<'ctx, P, E>> {
        match self {
            Value::Object(obj) => Some(obj),
            _ => None,
        }
    }

    pub fn into_object(self) -> Option<ObjectAsVec<'ctx, P, E>> {
        match self {
            Value::Object(obj) => Some(obj),
            _ => None,
        }
    }

    pub fn into_owned(self) -> Value<'static, P, E> {
        match self {
            Value::Null => Value::Null,
            Value::Bool(b) => Value::Bool(b),
            Value::Number(n) => Value::Number(n),
            Value::Element(e) => Value::Element(e),
            Value::Str(s) => Value::Str(Cow::Owned(s.into_owned())),
            Value::Array(arr) => {
                let owned_arr: Vec<Value<'static, P, E>> =
                    arr.into_iter().map(|v| v.into_owned()).collect();
                Value::Array(owned_arr)
            }
            Value::Object(obj) => Value::Object(
                obj.into_vec()
                    .into_iter()
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect(),
            ),
        }
    }

    pub fn into_expanded_object(self) -> impl Iterator<Item = (Key<'ctx, P>, Value<'ctx, P, E>)> {
        self.into_object()
            .map(|obj| obj.into_vec())
            .unwrap_or_default()
            .into_iter()
    }

    pub fn into_expanded_boolean_set(self) -> impl Iterator<Item = Key<'ctx, P>> {
        self.into_object()
            .map(|obj| obj.into_vec())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(key, value)| value.as_bool().filter(|&b| b).map(|_| key))
    }

    pub fn into_element(self) -> Option<E> {
        match self {
            Value::Element(element) => Some(element),
            _ => None,
        }
    }

    /// If the Value is a Boolean, returns the associated bool. Returns None otherwise.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// If the Value is a String, returns the associated str. Returns None otherwise.
    pub fn as_str(&self) -> Option<Cow<'_, str>> {
        match self {
            Value::Str(text) => Some(text.as_ref().into()),
            Value::Element(element) => Some(element.to_cow()),
            _ => None,
        }
    }

    pub fn into_string(self) -> Option<Cow<'ctx, str>> {
        match self {
            Value::Str(text) => Some(text),
            Value::Element(element) => Some(element.to_cow()),
            _ => None,
        }
    }

    pub fn into_owned_string(self) -> Option<String> {
        match self {
            Value::Str(text) => Some(text.into_owned()),
            Value::Element(element) => Some(element.to_cow().into_owned()),
            _ => None,
        }
    }

    /// If the Value is an integer, represent it as i64 if possible. Returns None otherwise.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Number(n) => n.as_i64(),
            _ => None,
        }
    }

    /// If the Value is an integer, represent it as u64 if possible. Returns None otherwise.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(n) => n.as_u64(),
            _ => None,
        }
    }

    /// If the Value is a number, represent it as f64 if possible. Returns None otherwise.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(n) => n.as_f64(),
            _ => None,
        }
    }
}

impl<P: Property, E: Element> From<bool> for Value<'_, P, E> {
    fn from(val: bool) -> Self {
        Value::Bool(val)
    }
}

impl<'a, P: Property, E: Element> From<&'a str> for Value<'a, P, E> {
    fn from(val: &'a str) -> Self {
        Value::Str(Cow::Borrowed(val))
    }
}

impl<P: Property, E: Element> From<String> for Value<'_, P, E> {
    fn from(val: String) -> Self {
        Value::Str(Cow::Owned(val))
    }
}

impl<'x, P: Property, E: Element> From<Cow<'x, str>> for Value<'x, P, E> {
    fn from(val: Cow<'x, str>) -> Self {
        Value::Str(val)
    }
}

impl<'a, P: Property, E: Element, T: Into<Value<'a, P, E>>> From<Vec<T>> for Value<'a, P, E> {
    fn from(val: Vec<T>) -> Self {
        Value::Array(val.into_iter().map(Into::into).collect())
    }
}

impl<'x, P: Property, E: Element, T: Into<Value<'x, P, E>>> From<Option<T>> for Value<'x, P, E> {
    fn from(val: Option<T>) -> Self {
        match val {
            Some(v) => v.into(),
            None => Value::Null,
        }
    }
}

impl<'x, P: Property, E: Element> From<E> for Value<'x, P, E> {
    fn from(element: E) -> Self {
        Value::Element(element)
    }
}

impl<'a, P: Property, E: Element, T: Clone + Into<Value<'a, P, E>>> From<&[T]> for Value<'a, P, E> {
    fn from(val: &[T]) -> Self {
        Value::Array(val.iter().map(Clone::clone).map(Into::into).collect())
    }
}

impl<P: Property, E: Element> Debug for Value<'_, P, E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => formatter.write_str("Null"),
            Value::Bool(boolean) => write!(formatter, "Bool({})", boolean),
            Value::Number(number) => match number.n {
                N::PosInt(n) => write!(formatter, "Number({:?})", n),
                N::NegInt(n) => write!(formatter, "Number({:?})", n),
                N::Float(n) => write!(formatter, "Number({:?})", n),
            },
            Value::Str(string) => write!(formatter, "Str({:?})", string),
            Value::Array(vec) => {
                formatter.write_str("Array ")?;
                Debug::fmt(vec, formatter)
            }
            Value::Object(map) => {
                formatter.write_str("Object ")?;
                Debug::fmt(map, formatter)
            }
            Value::Element(element) => write!(formatter, "Element({})", element.to_cow()),
        }
    }
}

// We just convert to serde_json::Value to Display
impl<P: Property, E: Element> Display for Value<'_, P, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::Value::from(self.clone()))
    }
}

impl<P: Property, E: Element> From<u64> for Value<'_, P, E> {
    fn from(val: u64) -> Self {
        Value::Number(val.into())
    }
}

impl<P: Property, E: Element> From<i64> for Value<'_, P, E> {
    fn from(val: i64) -> Self {
        Value::Number(val.into())
    }
}

impl<P: Property, E: Element> From<f64> for Value<'_, P, E> {
    fn from(val: f64) -> Self {
        Value::Number(val.into())
    }
}

impl<P: Property, E: Element> From<u32> for Value<'_, P, E> {
    fn from(val: u32) -> Self {
        Value::Number(val.into())
    }
}

impl<P: Property, E: Element> From<i32> for Value<'_, P, E> {
    fn from(val: i32) -> Self {
        Value::Number(val.into())
    }
}

impl<P: Property, E: Element> From<usize> for Value<'_, P, E> {
    fn from(val: usize) -> Self {
        Value::Number(val.into())
    }
}

impl<P: Property, E: Element> From<isize> for Value<'_, P, E> {
    fn from(val: isize) -> Self {
        Value::Number(val.into())
    }
}

impl<'ctx, P: Property, E: Element> From<ObjectAsVec<'ctx, P, E>> for Value<'ctx, P, E> {
    fn from(val: ObjectAsVec<'ctx, P, E>) -> Self {
        Value::Object(val)
    }
}

impl<P: Property, E: Element> From<Value<'_, P, E>> for serde_json::Value {
    fn from(val: Value<'_, P, E>) -> Self {
        match val {
            Value::Null => serde_json::Value::Null,
            Value::Bool(val) => serde_json::Value::Bool(val),
            Value::Number(val) => val.into_json_value(),
            Value::Str(val) => serde_json::Value::String(val.to_string()),
            Value::Array(vals) => {
                serde_json::Value::Array(vals.into_iter().map(|val| val.into()).collect())
            }
            Value::Object(vals) => serde_json::Value::Object(vals.into()),
            Value::Element(element) => serde_json::Value::String(element.to_cow().to_string()),
        }
    }
}

impl<P: Property, E: Element> From<&Value<'_, P, E>> for serde_json::Value {
    fn from(val: &Value<'_, P, E>) -> Self {
        match val {
            Value::Null => serde_json::Value::Null,
            Value::Bool(val) => serde_json::Value::Bool(*val),
            Value::Number(val) => val.into_json_value(),
            Value::Str(val) => serde_json::Value::String(val.to_string()),
            Value::Array(vals) => {
                serde_json::Value::Array(vals.iter().map(|val| val.into()).collect())
            }
            Value::Object(vals) => serde_json::Value::Object(vals.into()),
            Value::Element(element) => serde_json::Value::String(element.to_cow().to_string()),
        }
    }
}

impl<'ctx, P: Property, E: Element> From<&'ctx serde_json::Value> for Value<'ctx, P, E> {
    fn from(value: &'ctx serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(b) => Value::Bool(*b),
            serde_json::Value::Number(n) => {
                if let Some(n) = n.as_i64() {
                    Value::Number(n.into())
                } else if let Some(n) = n.as_u64() {
                    Value::Number(n.into())
                } else if let Some(n) = n.as_f64() {
                    Value::Number(n.into())
                } else {
                    unreachable!()
                }
            }
            serde_json::Value::String(val) => Value::Str(Cow::Borrowed(val)),
            serde_json::Value::Array(arr) => {
                let out: Vec<Value<'ctx, P, E>> = arr.iter().map(|v| v.into()).collect();
                Value::Array(out)
            }
            serde_json::Value::Object(obj) => {
                let mut ans = ObjectAsVec(Vec::with_capacity(obj.len()));
                for (k, v) in obj {
                    ans.insert(Key::Borrowed(k.as_str()), v);
                }
                Value::Object(ans)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Null;

impl Display for Null {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "null")
    }
}

impl AsRef<str> for Null {
    fn as_ref(&self) -> &str {
        "null"
    }
}

impl FromStr for Null {
    type Err = ();

    fn from_str(_: &str) -> Result<Self, Self::Err> {
        Err(())
    }
}

impl Property for Null {
    fn try_parse(_: Option<&Key<'_, Self>>, _: &str) -> Option<Self> {
        None
    }

    fn to_cow(&self) -> Cow<'static, str> {
        "".into()
    }
}

impl Element for Null {
    type Property = Null;

    fn try_parse<P>(_: &Key<'_, Self::Property>, _: &str) -> Option<Self> {
        None
    }

    fn to_cow(&self) -> Cow<'static, str> {
        "".into()
    }
}

impl Property for () {
    fn try_parse(_: Option<&Key<'_, Self>>, _: &str) -> Option<Self> {
        None
    }

    fn to_cow(&self) -> Cow<'static, str> {
        "".into()
    }
}

impl Element for () {
    type Property = ();

    fn try_parse<P>(_: &Key<'_, Self::Property>, _: &str) -> Option<Self> {
        None
    }

    fn to_cow(&self) -> Cow<'static, str> {
        "".into()
    }
}

