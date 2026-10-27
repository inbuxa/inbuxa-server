/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;

use crate::{
    icalendar::{ICalendar, ICalendarProperty, ICalendarValue, Uri},
    vcard::{VCard, VCardProperty, VCardValue},
};

pub(crate) fn distinct_size<'x>(binaries: impl Iterator<Item = &'x [u8]>) -> usize {
    let mut distinct: AHashSet<&[u8]> = AHashSet::new();
    let mut size = 0usize;

    for data in binaries {
        if distinct.insert(data) {
            size = size.saturating_add(data.len());
        }
    }

    size
}

impl ICalendar {
    pub fn blob_binaries(&self) -> impl Iterator<Item = &[u8]> {
        self.components
            .iter()
            .filter(|component| component.component_type.converts_links())
            .flat_map(|component| component.entries.iter())
            .filter(|entry| {
                matches!(
                    entry.name,
                    ICalendarProperty::Attach | ICalendarProperty::Image
                )
            })
            .filter_map(|entry| entry.values.first().and_then(ICalendarValue::binary_bytes))
    }

    pub fn embedded_binaries(&self) -> impl Iterator<Item = &[u8]> {
        self.components
            .iter()
            .flat_map(|component| component.entries.iter())
            .flat_map(|entry| entry.values.iter())
            .filter_map(|value| match value {
                ICalendarValue::Binary(data) => Some(data.as_slice()),
                ICalendarValue::Uri(Uri::Data(data)) => Some(data.data.as_slice()),
                _ => None,
            })
    }

    pub fn embedded_size(&self) -> usize {
        distinct_size(self.embedded_binaries())
    }
}

impl VCard {
    pub fn blob_binaries(&self) -> impl Iterator<Item = &[u8]> {
        self.entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.name,
                    VCardProperty::Photo | VCardProperty::Logo | VCardProperty::Sound
                )
            })
            .filter_map(|entry| match entry.values.first() {
                Some(VCardValue::Binary(data)) if !data.data.is_empty() => {
                    Some(data.data.as_slice())
                }
                _ => None,
            })
    }

    pub fn embedded_binaries(&self) -> impl Iterator<Item = &[u8]> {
        self.entries
            .iter()
            .flat_map(|entry| entry.values.iter())
            .filter_map(|value| match value {
                VCardValue::Binary(data) => Some(data.data.as_slice()),
                _ => None,
            })
    }

    pub fn embedded_size(&self) -> usize {
        distinct_size(self.embedded_binaries())
    }
}

#[cfg(feature = "rkyv")]
mod archived {
    use super::distinct_size;
    use crate::{
        icalendar::{
            ArchivedICalendar, ArchivedICalendarProperty, ArchivedICalendarValue, ArchivedUri,
        },
        vcard::{ArchivedVCard, ArchivedVCardProperty, ArchivedVCardValue},
    };

    impl ArchivedICalendar {
        pub fn blob_binaries(&self) -> impl Iterator<Item = &[u8]> {
            self.components
                .iter()
                .filter(|component| component.component_type.converts_links())
                .flat_map(|component| component.entries.iter())
                .filter(|entry| {
                    matches!(
                        entry.name,
                        ArchivedICalendarProperty::Attach | ArchivedICalendarProperty::Image
                    )
                })
                .filter_map(|entry| {
                    entry
                        .values
                        .first()
                        .and_then(ArchivedICalendarValue::binary_bytes)
                })
        }

        pub fn embedded_binaries(&self) -> impl Iterator<Item = &[u8]> {
            self.components
                .iter()
                .flat_map(|component| component.entries.iter())
                .flat_map(|entry| entry.values.iter())
                .filter_map(|value| match value {
                    ArchivedICalendarValue::Binary(data) => Some(data.as_ref()),
                    ArchivedICalendarValue::Uri(ArchivedUri::Data(data)) => {
                        Some(data.data.as_ref())
                    }
                    _ => None,
                })
        }

        pub fn embedded_size(&self) -> usize {
            distinct_size(self.embedded_binaries())
        }
    }

    impl ArchivedICalendarValue {
        pub(crate) fn binary_bytes(&self) -> Option<&[u8]> {
            match self {
                ArchivedICalendarValue::Binary(data) => Some(data.as_ref()),
                ArchivedICalendarValue::Uri(ArchivedUri::Data(data)) => Some(data.data.as_ref()),
                _ => None,
            }
            .filter(|data| !data.is_empty())
        }
    }

    impl ArchivedVCard {
        pub fn blob_binaries(&self) -> impl Iterator<Item = &[u8]> {
            self.entries
                .iter()
                .filter(|entry| {
                    matches!(
                        entry.name,
                        ArchivedVCardProperty::Photo
                            | ArchivedVCardProperty::Logo
                            | ArchivedVCardProperty::Sound
                    )
                })
                .filter_map(|entry| match entry.values.first() {
                    Some(ArchivedVCardValue::Binary(data)) if !data.data.is_empty() => {
                        Some(data.data.as_ref())
                    }
                    _ => None,
                })
        }

        pub fn embedded_binaries(&self) -> impl Iterator<Item = &[u8]> {
            self.entries
                .iter()
                .flat_map(|entry| entry.values.iter())
                .filter_map(|value| match value {
                    ArchivedVCardValue::Binary(data) => Some(data.data.as_ref()),
                    _ => None,
                })
        }

        pub fn embedded_size(&self) -> usize {
            distinct_size(self.embedded_binaries())
        }
    }
}

