/*
 * SPDX-FileCopyrightText: 2021 Pascal Seitz <pascal.seitz@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use core::hash::{Hash, Hasher};

/// Represents a JSON number, whether integer or floating point.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Number {
    pub(crate) n: N,
}

impl From<N> for Number {
    fn from(n: N) -> Self {
        Self { n }
    }
}

#[derive(Copy, Clone)]
pub(crate) enum N {
    PosInt(u64),
    /// Always less than zero.
    NegInt(i64),
    Float(f64),
}

impl Number {
    /// If the `Number` is an integer, represent it as i64 if possible. Returns
    /// None otherwise.
    pub fn as_u64(&self) -> Option<u64> {
        match self.n {
            N::PosInt(v) => Some(v),
            _ => None,
        }
    }
    /// If the `Number` is an integer, represent it as u64 if possible. Returns
    /// None otherwise.
    pub fn as_i64(&self) -> Option<i64> {
        match self.n {
            N::PosInt(n) => {
                if n <= i64::MAX as u64 {
                    Some(n as i64)
                } else {
                    None
                }
            }
            N::NegInt(v) => Some(v),
            _ => None,
        }
    }

    /// Represents the number as f64 if possible. Returns None otherwise.
    pub fn as_f64(&self) -> Option<f64> {
        match self.n {
            N::PosInt(n) => Some(n as f64),
            N::NegInt(n) => Some(n as f64),
            N::Float(n) => Some(n),
        }
    }

    /// Returns true if the `Number` is a f64.
    pub fn is_f64(&self) -> bool {
        matches!(self.n, N::Float(_))
    }

    /// Returns true if the `Number` is a u64.
    pub fn is_u64(&self) -> bool {
        matches!(self.n, N::PosInt(_))
    }

    /// Returns true if the `Number` is an integer between `i64::MIN` and
    /// `i64::MAX`.
    pub fn is_i64(&self) -> bool {
        match self.n {
            N::PosInt(v) => v <= i64::MAX as u64,
            N::NegInt(_) => true,
            N::Float(_) => false,
        }
    }

    pub fn cast_to_i64(self) -> i64 {
        match self.n {
            N::PosInt(v) => i64::try_from(v).unwrap_or(i64::MAX),
            N::NegInt(v) => v,
            N::Float(v) => v as i64,
        }
    }

    pub fn cast_to_u64(self) -> u64 {
        match self.n {
            N::PosInt(v) => v,
            N::NegInt(_) => 0,
            N::Float(v) => v as u64,
        }
    }

    pub fn try_cast_to_i64(self) -> Result<i64, f64> {
        match self.n {
            N::PosInt(v) => i64::try_from(v).map_err(|_| v as f64),
            N::NegInt(v) => Ok(v),
            N::Float(v) => Err(v),
        }
    }

    pub(crate) fn into_json_value(self) -> serde_json::Value {
        match self.n {
            N::PosInt(n) => serde_json::Value::Number(n.into()),
            N::NegInt(n) => serde_json::Value::Number(n.into()),
            N::Float(n) => serde_json::value::Number::from_f64(n)
                .map_or(serde_json::Value::Null, serde_json::Value::Number),
        }
    }
}

impl PartialEq for N {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (N::PosInt(a), N::PosInt(b)) => a == b,
            (N::NegInt(a), N::NegInt(b)) => a == b,
            (N::Float(a), N::Float(b)) => a == b || (a.is_nan() && b.is_nan()),
            _ => false,
        }
    }
}

impl Eq for N {}

impl Hash for N {
    fn hash<H: Hasher>(&self, h: &mut H) {
        match *self {
            N::PosInt(i) => i.hash(h),
            N::NegInt(i) => i.hash(h),
            N::Float(f) => {
                let bits = if f == 0.0 {
                    0.0f64.to_bits()
                } else if f.is_nan() {
                    f64::NAN.to_bits()
                } else {
                    f.to_bits()
                };
                bits.hash(h);
            }
        }
    }
}
impl From<u64> for Number {
    fn from(val: u64) -> Self {
        Self { n: N::PosInt(val) }
    }
}

impl From<i64> for Number {
    fn from(val: i64) -> Self {
        let n = match u64::try_from(val) {
            Ok(val) => N::PosInt(val),
            Err(_) => N::NegInt(val),
        };
        Self { n }
    }
}

impl From<f64> for Number {
    fn from(val: f64) -> Self {
        Self { n: N::Float(val) }
    }
}

impl From<usize> for Number {
    fn from(val: usize) -> Self {
        Self {
            n: N::PosInt(val as u64),
        }
    }
}

impl From<isize> for Number {
    fn from(val: isize) -> Self {
        Self::from(val as i64)
    }
}

impl From<u32> for Number {
    fn from(val: u32) -> Self {
        Self {
            n: N::PosInt(val as u64),
        }
    }
}

impl From<i32> for Number {
    fn from(val: i32) -> Self {
        Self::from(i64::from(val))
    }
}

impl TryFrom<Number> for serde_json::value::Number {
    type Error = f64;

    fn try_from(num: Number) -> Result<Self, Self::Error> {
        match num.n {
            N::PosInt(n) => Ok(n.into()),
            N::NegInt(n) => Ok(n.into()),
            N::Float(n) => serde_json::value::Number::from_f64(n).ok_or(n),
        }
    }
}

