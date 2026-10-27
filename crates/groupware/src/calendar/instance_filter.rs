/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    calendar::{
        identity::CalendarAddresses,
        participants::{ArchivedParticipantEntry, ParticipantVisibility},
    },
    strip_mailto_scheme,
};
use calcard::icalendar::{
    ArchivedICalendar, ArchivedICalendarComponent, ArchivedICalendarEntry,
    ArchivedICalendarParameterValue, ArchivedICalendarProperty, ArchivedICalendarValue,
};
use nlp::language::{
    Language,
    detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
};
use std::borrow::Cow;
use store::{
    ahash::AHashSet,
    search::{CalendarSearchField, SearchFilter, TextMatch, tokenize::tokenize},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttendeeSearch<'x> {
    All,
    VisibleTo(&'x CalendarAddresses),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct QueryWord {
    word: String,
    stem: Option<String>,
}

#[derive(Debug)]
struct TextCondition {
    fields: &'static [CalendarSearchField],
    op: TextMatch,
    language: Language,
    words: Vec<QueryWord>,
}

#[derive(Debug, Default)]
pub struct InstanceTextFilter {
    conditions: Vec<TextCondition>,
    ordered_fields: Vec<CalendarSearchField>,
}

pub struct EventTextFilter<'x> {
    conditions: &'x [TextCondition],
    ordered_fields: &'x [CalendarSearchField],
    language: Language,
    attendees: AttendeeSearch<'x>,
}

#[derive(Default)]
struct FieldTokens<'a> {
    words: AHashSet<Cow<'a, str>>,
    stemmed: AHashSet<Cow<'a, str>>,
    ordered: Vec<Cow<'a, str>>,
}

struct ComponentTokens<'a, 'x> {
    ordered_fields: &'x [CalendarSearchField],
    attendees: AttendeeSearch<'x>,
    fields: Vec<(CalendarSearchField, FieldTokens<'a>)>,
}

impl InstanceTextFilter {
    pub fn add(&mut self, fields: &'static [CalendarSearchField], filter: &SearchFilter) {
        let SearchFilter::Text {
            op,
            value,
            language,
            ..
        } = filter
        else {
            return;
        };
        let words = match op {
            TextMatch::Prefix => vec![QueryWord {
                word: value.to_lowercase(),
                stem: None,
            }],
            TextMatch::Standard | TextMatch::Exact => {
                let mut words = Vec::new();
                tokenize(value, *language, |token| {
                    words.push(QueryWord {
                        word: token.word.into_owned(),
                        stem: token.stem.map(Cow::into_owned),
                    });
                    true
                });
                if *op == TextMatch::Standard {
                    words.sort_unstable();
                    words.dedup();
                }
                words
            }
        };
        if *op == TextMatch::Exact {
            for field in fields {
                if !self.ordered_fields.contains(field) {
                    self.ordered_fields.push(*field);
                }
            }
        }
        self.conditions.push(TextCondition {
            fields,
            op: *op,
            language: *language,
            words,
        });
    }

    pub fn is_empty(&self) -> bool {
        self.conditions.is_empty()
    }

    pub fn for_event<'x>(
        &'x self,
        event: &ArchivedICalendar,
        default_language: Language,
        attendees: AttendeeSearch<'x>,
    ) -> EventTextFilter<'x> {
        let language = if self
            .conditions
            .iter()
            .flat_map(|condition| condition.fields)
            .any(|field| field.is_language_detected())
        {
            let mut detector = LanguageDetector::new();
            for value in event
                .components
                .iter()
                .filter(|component| component.component_type.is_scheduling_object())
                .flat_map(|component| {
                    field_values(component, CalendarSearchField::Title, AttendeeSearch::All).chain(
                        field_values(
                            component,
                            CalendarSearchField::Description,
                            AttendeeSearch::All,
                        ),
                    )
                })
            {
                detector.detect(value, MIN_LANGUAGE_SCORE);
            }
            detector
                .most_frequent_language()
                .unwrap_or(default_language)
        } else {
            default_language
        };

        EventTextFilter {
            conditions: &self.conditions,
            ordered_fields: &self.ordered_fields,
            language,
            attendees,
        }
    }
}

impl EventTextFilter<'_> {
    pub fn matches(&self, component: &ArchivedICalendarComponent) -> bool {
        let mut tokens = ComponentTokens {
            ordered_fields: self.ordered_fields,
            attendees: self.attendees,
            fields: Vec::with_capacity(2),
        };
        self.conditions
            .iter()
            .all(|condition| condition.matches(component, self.language, &mut tokens))
    }
}

impl<'a> ComponentTokens<'a, '_> {
    fn of(
        &mut self,
        component: &'a ArchivedICalendarComponent,
        field: CalendarSearchField,
        language: Language,
    ) -> &FieldTokens<'a> {
        if let Some(index) = self.fields.iter().position(|(cached, _)| *cached == field) {
            return &self.fields[index].1;
        }

        let keep_order = self.ordered_fields.contains(&field);
        let mut tokens = FieldTokens::default();
        for value in field_values(component, field, self.attendees) {
            tokenize(value, language, |token| {
                if keep_order {
                    tokens.ordered.push(token.word.clone());
                }
                if let Some(stem) = token.stem {
                    tokens.stemmed.insert(stem);
                }
                tokens.stemmed.insert(token.word.clone());
                tokens.words.insert(token.word);
                true
            });
        }
        &self.fields.push_mut((field, tokens)).1
    }
}

impl TextCondition {
    fn matches<'a>(
        &self,
        component: &'a ArchivedICalendarComponent,
        event_language: Language,
        tokens: &mut ComponentTokens<'a, '_>,
    ) -> bool {
        !self.words.is_empty()
            && self.fields.iter().any(|field| {
                let language = if field.is_language_detected() {
                    event_language
                } else {
                    Language::None
                };
                self.matches_tokens(tokens.of(component, *field, language))
            })
    }

    fn matches_tokens(&self, tokens: &FieldTokens<'_>) -> bool {
        match self.op {
            TextMatch::Standard => {
                let is_stemmed = !matches!(self.language, Language::None | Language::Unknown);
                self.words
                    .iter()
                    .all(|word| word.matches(tokens, is_stemmed))
            }
            TextMatch::Exact => tokens.ordered.windows(self.words.len()).any(|window| {
                window
                    .iter()
                    .zip(&self.words)
                    .all(|(token, word)| *token == word.word)
            }),
            TextMatch::Prefix => self.words.iter().all(|word| {
                tokens
                    .stemmed
                    .iter()
                    .any(|token| token.starts_with(&word.word))
            }),
        }
    }
}

impl QueryWord {
    fn matches(&self, tokens: &FieldTokens<'_>, is_stemmed: bool) -> bool {
        if is_stemmed {
            tokens.stemmed.contains(self.word.as_str())
                || self
                    .stem
                    .as_deref()
                    .is_some_and(|stem| tokens.stemmed.contains(stem))
        } else {
            tokens.words.contains(self.word.as_str())
        }
    }
}

trait DetectedLanguage {
    fn is_language_detected(&self) -> bool;
}

impl DetectedLanguage for CalendarSearchField {
    fn is_language_detected(&self) -> bool {
        matches!(
            self,
            CalendarSearchField::Title | CalendarSearchField::Description
        )
    }
}

fn field_values<'x>(
    component: &'x ArchivedICalendarComponent,
    field: CalendarSearchField,
    attendees: AttendeeSearch<'_>,
) -> impl Iterator<Item = &'x str> {
    component
        .entries
        .iter()
        .filter_map(move |entry| {
            let all_texts = match (&entry.name, field) {
                (ArchivedICalendarProperty::Summary, CalendarSearchField::Title)
                | (ArchivedICalendarProperty::Description, CalendarSearchField::Description)
                | (ArchivedICalendarProperty::Location, CalendarSearchField::Location)
                | (ArchivedICalendarProperty::Organizer, CalendarSearchField::Owner) => true,
                (ArchivedICalendarProperty::Attendee, CalendarSearchField::Owner)
                    if entry.has_owner_role() =>
                {
                    false
                }
                (ArchivedICalendarProperty::Attendee, CalendarSearchField::Attendee) => {
                    match attendees {
                        AttendeeSearch::All => true,
                        AttendeeSearch::VisibleTo(identities)
                            if entry.is_visible_participant(identities) =>
                        {
                            false
                        }
                        AttendeeSearch::VisibleTo(_) => return None,
                    }
                }
                _ => return None,
            };
            Some((entry, all_texts))
        })
        .flat_map(|(entry, all_texts)| entry_texts(entry, all_texts))
        .map(strip_mailto_scheme)
}

fn entry_texts(entry: &ArchivedICalendarEntry, all_texts: bool) -> impl Iterator<Item = &str> {
    entry.name_and_address().filter(move |_| !all_texts).chain(
        entry
            .values
            .iter()
            .filter_map(|value| match value {
                ArchivedICalendarValue::Text(value) => Some(value.as_str()),
                ArchivedICalendarValue::Uri(uri) => uri.as_str(),
                _ => None,
            })
            .chain(entry.params.iter().filter_map(|param| match &param.value {
                ArchivedICalendarParameterValue::Text(value) => Some(value.as_str()),
                ArchivedICalendarParameterValue::Uri(uri) => uri.as_str(),
                _ => None,
            }))
            .filter(move |_| all_texts),
    )
}

