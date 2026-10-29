/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! What a sharee of a calendar may see of an event: nothing of a secret
//! (CLASS:CONFIDENTIAL) event, the time only of a private one, and only the
//! owners and themselves among the attendees of an event that hides them.

use super::{ArchivedCalendarEvent, CalendarEvent, EVENT_HIDE_ATTENDEES};
use crate::scheduling::{ItipField, ItipMessage, ItipSummary, ItipValue};
use calcard::icalendar::{
    ArchivedICalendarClassification, ArchivedICalendarProperty, ArchivedICalendarValue, ICalendar,
    ICalendarClassification, ICalendarComponentType, ICalendarParameterName,
    ICalendarParameterValue, ICalendarParticipationRole, ICalendarProperty, ICalendarValue,
};
use common::{EVENT_VIEW_HIDE_ATTENDEES, EVENT_VIEW_PRIVATE, EVENT_VIEW_SECRET};

pub fn event_view(event: &CalendarEvent) -> u8 {
    let mut view = 0;
    for entry in event
        .data
        .event
        .components
        .iter()
        .filter(|comp| comp.component_type.is_scheduling_object())
        .flat_map(|comp| comp.entries.iter())
        .filter(|entry| entry.name == ICalendarProperty::Class)
    {
        view |= match entry.values.first() {
            Some(ICalendarValue::Classification(ICalendarClassification::Public)) | None => 0,
            Some(ICalendarValue::Classification(ICalendarClassification::Confidential)) => {
                EVENT_VIEW_SECRET
            }
            // An unknown class counts as private
            _ => EVENT_VIEW_PRIVATE,
        };
    }
    if event.flags & EVENT_HIDE_ATTENDEES != 0 {
        view |= EVENT_VIEW_HIDE_ATTENDEES;
    }
    view
}

pub fn archived_event_view(event: &ArchivedCalendarEvent) -> u8 {
    let mut view = 0;
    for entry in event
        .data
        .event
        .components
        .iter()
        .filter(|comp| comp.component_type.is_scheduling_object())
        .flat_map(|comp| comp.entries.iter())
        .filter(|entry| matches!(entry.name, ArchivedICalendarProperty::Class))
    {
        view |= match entry.values.first() {
            Some(ArchivedICalendarValue::Classification(
                ArchivedICalendarClassification::Public,
            ))
            | None => 0,
            Some(ArchivedICalendarValue::Classification(
                ArchivedICalendarClassification::Confidential,
            )) => EVENT_VIEW_SECRET,
            _ => EVENT_VIEW_PRIVATE,
        };
    }
    if event.flags.to_native() & EVENT_HIDE_ATTENDEES != 0 {
        view |= EVENT_VIEW_HIDE_ATTENDEES;
    }
    view
}

/// Keeps only the time and basic metadata of a private event (RFC 8984,
/// section 4.4.3), with its recurrence so its occurrences stay right.
pub fn redact_private_event(ical: &mut ICalendar) {
    let mut remove_ids = Vec::new();
    for (comp_id, comp) in ical.components.iter_mut().enumerate() {
        match comp.component_type {
            ICalendarComponentType::VCalendar => {
                comp.entries.retain(|entry| {
                    matches!(
                        entry.name,
                        ICalendarProperty::Prodid
                            | ICalendarProperty::Version
                            | ICalendarProperty::Calscale
                    )
                });
            }
            ICalendarComponentType::VTimezone
            | ICalendarComponentType::Standard
            | ICalendarComponentType::Daylight => {}
            ref component_type if component_type.is_scheduling_object() => {
                comp.entries.retain(|entry| {
                    matches!(
                        entry.name,
                        ICalendarProperty::Dtstart
                            | ICalendarProperty::Dtend
                            | ICalendarProperty::Duration
                            | ICalendarProperty::Due
                            | ICalendarProperty::Rrule
                            | ICalendarProperty::Rdate
                            | ICalendarProperty::Exdate
                            | ICalendarProperty::Exrule
                            | ICalendarProperty::RecurrenceId
                            | ICalendarProperty::Uid
                            | ICalendarProperty::Sequence
                            | ICalendarProperty::Dtstamp
                            | ICalendarProperty::Created
                            | ICalendarProperty::LastModified
                            | ICalendarProperty::Class
                            | ICalendarProperty::Transp
                    )
                });
                for entry in &mut comp.entries {
                    entry.params.retain(|param| {
                        matches!(
                            param.name,
                            ICalendarParameterName::Tzid
                                | ICalendarParameterName::Value
                                | ICalendarParameterName::Range
                        )
                    });
                }
            }
            _ => remove_ids.push(comp_id as u32),
        }
    }
    if !remove_ids.is_empty() {
        ical.remove_component_ids(&remove_ids);
    }
}

/// Keeps only the attendees with the owner role and those at `addresses`
pub fn hide_attendees(ical: &mut ICalendar, addresses: &[String]) {
    for component in &mut ical.components {
        if component.component_type.is_scheduling_object() {
            component.entries.retain(|entry| match &entry.name {
                ICalendarProperty::Attendee => {
                    entry.parameters(&ICalendarParameterName::Role).any(|role| {
                        matches!(
                            role,
                            ICalendarParameterValue::Role(ICalendarParticipationRole::Owner,)
                        )
                    }) || entry
                        .calendar_address()
                        .is_some_and(|addr| addresses.iter().any(|a| a.eq_ignore_ascii_case(addr)))
                }
                _ => true,
            });
        }
    }
}

/// An organizer's scheduling messages for an event that hides its attendees
/// go to each recipient on its own and name no attendee but the organizer,
/// the owners and that recipient.
pub fn itip_hide_attendees(messages: Vec<ItipMessage<ICalendar>>) -> Vec<ItipMessage<ICalendar>> {
    let mut result = Vec::with_capacity(messages.len());
    for message in messages {
        if !message.from_organizer {
            result.push(message);
            continue;
        }
        for rcpt in &message.to {
            let mut ical = message.message.clone();
            for component in &mut ical.components {
                if component.component_type.is_scheduling_object() {
                    let organizer = component
                        .property(&ICalendarProperty::Organizer)
                        .and_then(|entry| entry.calendar_address())
                        .map(|addr| addr.to_string());
                    component.entries.retain(|entry| {
                        entry.name != ICalendarProperty::Attendee
                            || entry.parameters(&ICalendarParameterName::Role).any(|role| {
                                matches!(
                                    role,
                                    ICalendarParameterValue::Role(
                                        ICalendarParticipationRole::Owner
                                    )
                                )
                            })
                            || entry.calendar_address().is_some_and(|addr| {
                                addr.eq_ignore_ascii_case(rcpt)
                                    || organizer.as_deref().is_some_and(|organizer| {
                                        addr.eq_ignore_ascii_case(organizer)
                                    })
                            })
                    });
                }
            }
            let mut summary = message.summary.clone();
            match &mut summary {
                ItipSummary::Invite(fields)
                | ItipSummary::Cancel(fields)
                | ItipSummary::Rsvp {
                    current: fields, ..
                } => hide_summary_attendees(fields, rcpt),
                ItipSummary::Update {
                    current, previous, ..
                } => {
                    hide_summary_attendees(current, rcpt);
                    hide_summary_attendees(previous, rcpt);
                }
            }
            result.push(ItipMessage {
                from: message.from.clone(),
                from_organizer: true,
                to: vec![rcpt.clone()],
                summary,
                message: ical,
            });
        }
    }
    result
}

fn hide_summary_attendees(fields: &mut [ItipField], rcpt: &str) {
    for field in fields {
        if let ItipValue::Participants(participants) = &mut field.value {
            participants.retain(|participant| {
                participant.is_organizer || participant.email.eq_ignore_ascii_case(rcpt)
            });
        }
    }
}

/// The scheduling messages of an event with these flags as they may be sent
pub fn itip_messages_for(
    messages: Vec<ItipMessage<ICalendar>>,
    event_flags: u16,
) -> Vec<ItipMessage<ICalendar>> {
    if event_flags & EVENT_HIDE_ATTENDEES != 0 {
        itip_hide_attendees(messages)
    } else {
        messages
    }
}
