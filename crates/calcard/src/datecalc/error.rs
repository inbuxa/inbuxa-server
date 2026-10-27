/*
 * SPDX-FileCopyrightText: 2021 Fredrik Meringdal, Ralph Bisschops <https://github.com/fmeringdal/rust-rrule>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::{
    common::{CalendarScale, IanaString},
    icalendar::ICalendarFrequency,
};
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize)
)]
pub enum RRuleError {
    ValidationError(ValidationError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize)
)]
pub enum ValidationError {
    BySetPosWithoutByRule,
    InvalidFieldValue {
        field: String,
        value: String,
    },
    InvalidFieldValueRange {
        field: String,
        value: String,
        start_idx: String,
        end_idx: String,
    },
    InvalidFieldValueRangeWithFreq {
        field: String,
        value: String,
        freq: ICalendarFrequency,
        start_idx: String,
        end_idx: String,
    },
    InvalidByRuleAndFrequency {
        by_rule: String,
        freq: ICalendarFrequency,
    },
    TooBigInterval(u16),
    /// The rule is written in a calendar other than the Gregorian one.
    ///
    /// RFC 7529 scales place instances on entirely different dates, so a rule
    /// naming one cannot be expanded by treating the scale as absent.
    UnsupportedCalendarScale(CalendarScale),
}

impl From<ValidationError> for RRuleError {
    fn from(err: ValidationError) -> Self {
        Self::ValidationError(err)
    }
}

impl Display for RRuleError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RRuleError::ValidationError(err) => write!(f, "{err}"),
        }
    }
}

impl Display for ValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::BySetPosWithoutByRule => {
                write!(f, "BYSETPOS without BYxxx rule is not allowed")
            }
            ValidationError::InvalidFieldValue { field, value } => {
                write!(f, "Invalid value `{value}` for field `{field}`")
            }
            ValidationError::InvalidFieldValueRange {
                field,
                value,
                start_idx,
                end_idx,
            } => write!(
                f,
                "Invalid value `{value}` for field `{field}`, start index `{start_idx}` and end index `{end_idx}`"
            ),
            ValidationError::InvalidFieldValueRangeWithFreq {
                field,
                value,
                freq,
                start_idx,
                end_idx,
            } => write!(
                f,
                "Invalid value `{value}` for field `{field}`, frequency `{}`, start index `{start_idx}` and end index `{end_idx}`",
                freq.as_str()
            ),
            ValidationError::InvalidByRuleAndFrequency { by_rule, freq } => write!(
                f,
                "Invalid BY rule `{by_rule}` with frequency `{}`",
                freq.as_str()
            ),
            ValidationError::TooBigInterval(interval) => write!(
                f,
                "Interval of {interval} is too big. The maximum interval is 32767."
            ),
            ValidationError::UnsupportedCalendarScale(rscale) => write!(
                f,
                "Recurrence rules in the {} calendar are not supported",
                rscale.as_str()
            ),
        }
    }
}
