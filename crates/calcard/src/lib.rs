/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
#![deny(rust_2018_idioms)]
#![forbid(unsafe_code)]
use common::tokenizer::{Mode, StopChar, Token};
use icalendar::{ICalendar, ICalendarComponentType};
use std::borrow::Cow;
use vcard::VCard;

pub mod common;
pub mod datecalc;
pub mod icalendar;
#[cfg(feature = "jmap")]
pub mod jscalendar;
#[cfg(feature = "jmap")]
pub mod jscontact;
pub mod vcard;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Entry {
    VCard(VCard),
    ICalendar(ICalendar),
    InvalidLine(String),
    UnexpectedComponentEnd {
        expected: ICalendarComponentType,
        found: ICalendarComponentType,
    },
    UnterminatedComponent(Cow<'static, str>),
    TooManyComponents,
    Eof,
}

const PRESIZE_BYTES_PER_SLOT: usize = 8;

pub struct Parser<'x> {
    pub(crate) input: &'x [u8],
    pub(crate) source: &'x str,
    pub(crate) pos: usize,
    pub(crate) strict: bool,
    pub(crate) mode: Mode,
    pub(crate) token_buf: Vec<Token<'x>>,
    pub(crate) last_token_end: usize,
    presize_budget: usize,
}

impl<'x> Parser<'x> {
    pub fn new(input: &'x str) -> Self {
        Self {
            input: input.as_bytes(),
            source: input,
            pos: 0,
            strict: false,
            mode: Mode::INITIAL,
            token_buf: Vec::new(),
            last_token_end: usize::MAX,
            presize_budget: input.len() / PRESIZE_BYTES_PER_SLOT,
        }
    }

    pub fn strict(mut self) -> Self {
        self.strict = true;
        self
    }

    pub(crate) fn presize<T>(&mut self, items: &mut Vec<T>, hint: usize) {
        let slots = hint.min(self.presize_budget);
        self.presize_budget -= slots;
        items.reserve_exact(slots);
    }

    pub fn entry(&mut self) -> Entry {
        self.expect_iana_token();

        loop {
            if let Some(token) = self.token() {
                if (token.text.eq_ignore_ascii_case(b"BEGIN")
                    || token.text.eq_ignore_ascii_case("\u{feff}BEGIN".as_bytes()))
                    && token.stop_char == StopChar::Colon
                {
                    if let Some(token) = self.token() {
                        if token.stop_char == StopChar::Lf {
                            hashify::fnc_map_ignore_case!(token.text.as_ref(),
                                b"VCARD" => { return self.vcard(); },
                                b"VCALENDAR" => { return self.icalendar(ICalendarComponentType::VCalendar); },
                                b"VEVENT" => { return self.icalendar(ICalendarComponentType::VEvent); },
                                b"VTODO" => { return self.icalendar(ICalendarComponentType::VTodo); },
                                b"VJOURNAL" => { return self.icalendar(ICalendarComponentType::VJournal); },
                                b"VFREEBUSY" => { return self.icalendar(ICalendarComponentType::VFreebusy); },
                                b"VTIMEZONE" => { return self.icalendar(ICalendarComponentType::VTimezone); },
                                b"VALARM" => { return self.icalendar(ICalendarComponentType::VAlarm); },
                                b"STANDARD" => { return self.icalendar(ICalendarComponentType::Standard); },
                                b"DAYLIGHT" => { return self.icalendar(ICalendarComponentType::Daylight); },
                                b"VAVAILABILITY" => { return self.icalendar(ICalendarComponentType::VAvailability); },
                                b"AVAILABLE" => { return self.icalendar(ICalendarComponentType::Available); },
                                b"PARTICIPANT" => { return self.icalendar(ICalendarComponentType::Participant); },
                                b"VLOCATION" => { return self.icalendar(ICalendarComponentType::VLocation); },
                                b"VRESOURCE" => { return self.icalendar(ICalendarComponentType::VResource); },
                                _ => {
                                    return self.icalendar(ICalendarComponentType::Other(token.into_string()));
                                }
                            )
                        }
                    } else {
                        return Entry::Eof;
                    }
                }

                let token_start = token.start;
                let mut token_end = token.end;

                if token.stop_char != StopChar::Lf {
                    self.expect_single_value();
                    while let Some(token) = self.token() {
                        token_end = token.end;
                        if token.stop_char == StopChar::Lf {
                            break;
                        }
                    }
                } else if token.text.is_empty() {
                    continue;
                }

                return Entry::InvalidLine(
                    self.source
                        .get(token_start..=token_end)
                        .unwrap_or_default()
                        .to_string(),
                );
            } else {
                return Entry::Eof;
            }
        }
    }
}
