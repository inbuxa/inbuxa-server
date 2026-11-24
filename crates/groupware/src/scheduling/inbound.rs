/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    calendar::dates::has_oversized_rrule,
    scheduling::{
        Attendee, InstanceId, ItipError, ItipMessage, ItipSnapshot, ItipSnapshots,
        organizer::organizer_request_full,
    },
};
use ahash::AHashSet;
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarMethod,
        ICalendarParameter, ICalendarParameterName, ICalendarProperty, ICalendarStatus,
        ICalendarValue, Uri,
    },
};

#[derive(Debug)]
pub enum MergeAction {
    AddEntries {
        component_id: u16,
        entries: Vec<ICalendarEntry>,
    },
    RemoveEntries {
        component_id: u16,
        entries: AHashSet<ICalendarProperty>,
    },
    AddParameters {
        component_id: u16,
        entry_id: u16,
        parameters: Vec<ICalendarParameter>,
    },
    RemoveParameters {
        component_id: u16,
        entry_id: u16,
        parameters: Vec<ICalendarParameterName>,
    },
    AddComponent {
        component: ICalendarComponent,
    },
    RemoveComponent {
        component_id: u16,
    },
}

pub enum MergeResult {
    Actions(Vec<MergeAction>),
    Message(ItipMessage<ICalendar>),
    None,
}

pub fn itip_process_message(
    ical: &ICalendar,
    snapshots: ItipSnapshots<'_>,
    itip: &ICalendar,
    itip_snapshots: ItipSnapshots<'_>,
    sender: String,
    max_instances: usize,
) -> Result<MergeResult, ItipError> {
    if snapshots.organizer.email != itip_snapshots.organizer.email {
        return Err(ItipError::OrganizerMismatch);
    }

    let method = itip_method(itip)?;
    let mut merge_actions = Vec::new();

    if snapshots.organizer.email.is_local {
        // Handle attendee updates
        if snapshots.organizer.email.email == sender {
            return Err(ItipError::OrganizerIsLocalAddress);
        }
        match method {
            ICalendarMethod::Reply => {
                handle_reply(
                    ical,
                    &snapshots,
                    &itip_snapshots,
                    &sender,
                    max_instances,
                    &mut merge_actions,
                )?;
            }
            ICalendarMethod::Refresh => {
                // inbuxa: only a current attendee may ask for the event again
                if !snapshots
                    .components
                    .values()
                    .any(|snapshot| snapshot.attendee_by_email(&sender).is_some())
                {
                    return Err(ItipError::SenderIsNotParticipant(sender));
                }
                return organizer_request_full(ical, &snapshots, None, false).and_then(
                    |messages| {
                        messages
                            .into_iter()
                            .next()
                            .map(|mut message| {
                                message.to = vec![sender];
                                MergeResult::Message(message)
                            })
                            .ok_or(ItipError::NothingToSend)
                    },
                );
            }
            _ => return Err(ItipError::UnsupportedMethod(method.clone())),
        }
    } else {
        itip_snapshots.assert_organizer_sends(method, &sender)?;

        // Handle organizer and attendees updates
        match method {
            ICalendarMethod::Request => {
                let mut is_full_update = false;
                for (instance_id, itip_snapshot) in &itip_snapshots.components {
                    is_full_update = is_full_update || instance_id == &InstanceId::Main;
                    let itip_component = &itip.components[itip_snapshot.comp_id as usize];

                    if let Some(snapshot) = snapshots.components.get(instance_id) {
                        // Merge instances
                        if itip_snapshot.sequence.unwrap_or_default()
                            >= snapshot.sequence.unwrap_or_default()
                        {
                            let mut changed_entries = itip_snapshot
                                .entries
                                .symmetric_difference(&snapshot.entries)
                                .map(|entry| entry.name.clone())
                                .collect::<AHashSet<_>>();
                            if itip_snapshot.attendees != snapshot.attendees {
                                changed_entries.insert(ICalendarProperty::Attendee);
                            }
                            if itip_snapshot.dtstamp.is_some()
                                && itip_snapshot.dtstamp != snapshot.dtstamp
                            {
                                changed_entries.insert(ICalendarProperty::Dtstamp);
                            }
                            changed_entries.insert(ICalendarProperty::Sequence);

                            if !changed_entries.is_empty() {
                                let entries = itip_component
                                    .entries
                                    .iter()
                                    .filter(|entry| changed_entries.contains(&entry.name))
                                    .cloned()
                                    .collect();
                                merge_actions.push(MergeAction::RemoveEntries {
                                    component_id: snapshot.comp_id,
                                    entries: changed_entries,
                                });
                                merge_actions.push(MergeAction::AddEntries {
                                    component_id: snapshot.comp_id,
                                    entries,
                                });
                            }
                        } else {
                            return Err(ItipError::OutOfSequence);
                        }
                    } else {
                        // Add instance
                        merge_actions.push(MergeAction::AddComponent {
                            component: ICalendarComponent {
                                component_type: itip_component.component_type.clone(),
                                entries: itip_component
                                    .entries
                                    .iter()
                                    .filter(|entry| {
                                        !matches!(entry.name, ICalendarProperty::Other(_))
                                    })
                                    .cloned()
                                    .collect(),
                                component_ids: vec![],
                            },
                        });
                    }
                }

                if is_full_update {
                    for (instance_id, snapshot) in &snapshots.components {
                        if !itip_snapshots.components.contains_key(instance_id) {
                            // Remove instance
                            merge_actions.push(MergeAction::RemoveComponent {
                                component_id: snapshot.comp_id,
                            });
                        }
                    }
                }
            }
            ICalendarMethod::Add => {
                for (instance_id, itip_snapshot) in &itip_snapshots.components {
                    if !snapshots.components.contains_key(instance_id) {
                        let itip_component = &itip.components[itip_snapshot.comp_id as usize];
                        merge_actions.push(MergeAction::AddComponent {
                            component: ICalendarComponent {
                                component_type: itip_component.component_type.clone(),
                                entries: itip_component
                                    .entries
                                    .iter()
                                    .filter(|entry| {
                                        !matches!(entry.name, ICalendarProperty::Other(_))
                                    })
                                    .cloned()
                                    .collect(),
                                component_ids: vec![],
                            },
                        });
                    }
                }
            }
            ICalendarMethod::Cancel => {
                let mut cancel_all_instances = false;
                for (instance_id, itip_snapshot) in &itip_snapshots.components {
                    if let Some(snapshot) = snapshots.components.get(instance_id) {
                        if itip_snapshot.sequence.unwrap_or_default()
                            >= snapshot.sequence.unwrap_or_default()
                        {
                            // Cancel instance
                            let itip_component = itip_snapshot.comp;
                            merge_actions.push(MergeAction::RemoveEntries {
                                component_id: snapshot.comp_id,
                                entries: [
                                    ICalendarProperty::Organizer,
                                    ICalendarProperty::Attendee,
                                    ICalendarProperty::Status,
                                    ICalendarProperty::Sequence,
                                ]
                                .into_iter()
                                .collect(),
                            });
                            merge_actions.push(MergeAction::AddEntries {
                                component_id: snapshot.comp_id,
                                entries: itip_component
                                    .entries
                                    .iter()
                                    .filter(|entry| {
                                        matches!(
                                            entry.name,
                                            ICalendarProperty::Organizer
                                                | ICalendarProperty::Attendee
                                        )
                                    })
                                    .cloned()
                                    .chain([ICalendarEntry {
                                        name: ICalendarProperty::Status,
                                        params: vec![],
                                        values: vec![ICalendarValue::Status(
                                            ICalendarStatus::Cancelled,
                                        )],
                                    }])
                                    .collect(),
                            });
                            cancel_all_instances =
                                cancel_all_instances || instance_id == &InstanceId::Main;
                        } else {
                            return Err(ItipError::OutOfSequence);
                        }
                    } else {
                        let itip_component = itip_snapshot.comp;
                        merge_actions.push(MergeAction::AddComponent {
                            component: ICalendarComponent {
                                component_type: itip_component.component_type.clone(),
                                entries: itip_component
                                    .entries
                                    .iter()
                                    .filter(|entry| {
                                        !matches!(
                                            entry.name,
                                            ICalendarProperty::Status | ICalendarProperty::Other(_)
                                        )
                                    })
                                    .cloned()
                                    .chain([ICalendarEntry {
                                        name: ICalendarProperty::Status,
                                        params: vec![],
                                        values: vec![ICalendarValue::Status(
                                            ICalendarStatus::Cancelled,
                                        )],
                                    }])
                                    .collect(),
                                component_ids: vec![],
                            },
                        });
                    }
                }

                if cancel_all_instances {
                    // Remove all instances
                    let itip_main = itip_snapshots.components.get(&InstanceId::Main).unwrap();
                    let itip_component = itip_main.comp;
                    for (instance_id, snapshot) in &snapshots.components {
                        if !itip_snapshots.components.contains_key(instance_id) {
                            merge_actions.push(MergeAction::RemoveEntries {
                                component_id: snapshot.comp_id,
                                entries: [
                                    ICalendarProperty::Organizer,
                                    ICalendarProperty::Attendee,
                                    ICalendarProperty::Status,
                                ]
                                .into_iter()
                                .collect(),
                            });
                            merge_actions.push(MergeAction::AddEntries {
                                component_id: snapshot.comp_id,
                                entries: itip_component
                                    .entries
                                    .iter()
                                    .filter(|entry| {
                                        matches!(
                                            entry.name,
                                            ICalendarProperty::Organizer
                                                | ICalendarProperty::Attendee
                                        )
                                    })
                                    .cloned()
                                    .chain([ICalendarEntry {
                                        name: ICalendarProperty::Status,
                                        params: vec![],
                                        values: vec![ICalendarValue::Status(
                                            ICalendarStatus::Cancelled,
                                        )],
                                    }])
                                    .collect(),
                            });
                        }
                    }
                }
            }
            ICalendarMethod::Reply
                if itip_snapshots.components.values().any(|snapshot| {
                    snapshot.external_attendees().any(|a| {
                        a.email.email == sender && a.delegated_from.iter().any(|a| a.is_local)
                    })
                }) =>
            {
                handle_reply(
                    ical,
                    &snapshots,
                    &itip_snapshots,
                    &sender,
                    max_instances,
                    &mut merge_actions,
                )?;
            }
            _ => return Err(ItipError::UnsupportedMethod(method.clone())),
        }
    }

    if !merge_actions.is_empty() {
        Ok(MergeResult::Actions(merge_actions))
    } else {
        Ok(MergeResult::None)
    }
}

pub fn itip_import_message(ical: &mut ICalendar) -> Result<(), ItipError> {
    let mut expect_object_type = None;
    for comp in ical.components.iter_mut() {
        if comp.component_type.is_scheduling_object() {
            match expect_object_type {
                Some(expected) if expected != &comp.component_type => {
                    return Err(ItipError::MultipleObjectTypes);
                }
                None => {
                    expect_object_type = Some(&comp.component_type);
                }
                _ => {}
            }
        } else if comp.component_type == ICalendarComponentType::VCalendar {
            comp.entries
                .retain(|entry| !matches!(entry.name, ICalendarProperty::Method));
        }
    }

    Ok(())
}

fn handle_reply(
    ical: &ICalendar,
    snapshots: &ItipSnapshots<'_>,
    itip_snapshots: &ItipSnapshots<'_>,
    sender: &str,
    max_instances: usize,
    merge_actions: &mut Vec<MergeAction>,
) -> Result<(), ItipError> {
    let mut occurrences = None;

    for (instance_id, itip_snapshot) in &itip_snapshots.components {
        if let Some(snapshot) = snapshots.components.get(instance_id) {
            if let (Some(attendee), Some(updated_attendee)) = (
                snapshot.attendee_by_email(sender),
                itip_snapshot.attendee_by_email(sender),
            ) {
                let itip_component = itip_snapshot.comp;
                let changed_part_stat = attendee.part_stat != updated_attendee.part_stat;
                let changed_rsvp = attendee.rsvp != updated_attendee.rsvp;
                let changed_delegated_to = attendee.delegated_to != updated_attendee.delegated_to;
                let has_request_status = !itip_snapshot.request_status.is_empty();

                if changed_part_stat || changed_rsvp || changed_delegated_to || has_request_status {
                    // Update participant status
                    let (remove_parameters, add_parameters) =
                        reply_parameters(attendee, updated_attendee, itip_snapshot);

                    merge_actions.push(MergeAction::RemoveParameters {
                        component_id: snapshot.comp_id,
                        entry_id: attendee.entry_id,
                        parameters: remove_parameters,
                    });
                    merge_actions.push(MergeAction::AddParameters {
                        component_id: snapshot.comp_id,
                        entry_id: attendee.entry_id,
                        parameters: add_parameters,
                    });

                    // Add unknown delegated attendees
                    for delegated_to in &updated_attendee.delegated_to {
                        if let Some(itip_delegated) =
                            itip_snapshot.attendee_by_email(&delegated_to.email)
                        {
                            if let Some(delegated) = snapshot.attendee_by_email(&delegated_to.email)
                            {
                                if delegated != itip_delegated {
                                    merge_actions.push(MergeAction::RemoveParameters {
                                        component_id: snapshot.comp_id,
                                        entry_id: delegated.entry_id,
                                        parameters: vec![
                                            ICalendarParameterName::DelegatedTo,
                                            ICalendarParameterName::DelegatedFrom,
                                            ICalendarParameterName::Partstat,
                                            ICalendarParameterName::Rsvp,
                                            ICalendarParameterName::ScheduleStatus,
                                            ICalendarParameterName::Role,
                                        ],
                                    });
                                    merge_actions.push(MergeAction::AddParameters {
                                        component_id: snapshot.comp_id,
                                        entry_id: delegated.entry_id,
                                        parameters: itip_component.entries
                                            [itip_delegated.entry_id as usize]
                                            .params
                                            .iter()
                                            .filter(|param| {
                                                matches!(
                                                    param.name,
                                                    ICalendarParameterName::DelegatedTo
                                                        | ICalendarParameterName::DelegatedFrom
                                                        | ICalendarParameterName::Partstat
                                                        | ICalendarParameterName::Rsvp
                                                        | ICalendarParameterName::ScheduleStatus
                                                        | ICalendarParameterName::Role
                                                )
                                            })
                                            .cloned()
                                            .collect(),
                                    });
                                }
                            } else {
                                merge_actions.push(MergeAction::AddEntries {
                                    component_id: snapshot.comp_id,
                                    entries: vec![
                                        itip_component.entries[itip_delegated.entry_id as usize]
                                            .clone(),
                                    ],
                                });
                            }
                        }
                    }
                }

                // Add changed properties for VTODO
                if snapshot.comp.component_type == ICalendarComponentType::VTodo {
                    let mut remove_entries = AHashSet::new();
                    let mut add_entries = Vec::new();

                    for entry in itip_component.entries.iter() {
                        if matches!(
                            entry.name,
                            ICalendarProperty::PercentComplete
                                | ICalendarProperty::Status
                                | ICalendarProperty::Completed
                        ) {
                            remove_entries.insert(entry.name.clone());
                            add_entries.push(entry.clone());
                        }
                    }

                    if !add_entries.is_empty() {
                        merge_actions.push(MergeAction::RemoveEntries {
                            component_id: snapshot.comp_id,
                            entries: remove_entries,
                        });
                        merge_actions.push(MergeAction::AddEntries {
                            component_id: snapshot.comp_id,
                            entries: add_entries,
                        });
                    }
                }
            } else {
                return Err(ItipError::SenderIsNotParticipant(sender.to_string()));
            }
        } else if let (InstanceId::Recurrence(recurrence_id), Some(updated_attendee)) =
            (instance_id, itip_snapshot.attendee_by_email(sender))
        {
            // inbuxa: an answer for an instance the organizer hasn't changed must
            // come from an attendee of the series and name one of its dates. The
            // new instance keeps the organizer's own ORGANIZER, UID and SEQUENCE
            // and takes only the sender's answer from the reply.
            let Some(series) = snapshots.components.get(&InstanceId::Main) else {
                continue;
            };
            let Some(attendee) = series.attendee_by_email(sender) else {
                return Err(ItipError::SenderIsNotParticipant(sender.to_string()));
            };
            if !occurrences
                .get_or_insert_with(|| series_occurrences(ical, series.comp_id, max_instances))
                .contains(&recurrence_id.date)
            {
                continue;
            }

            let itip_component = itip_snapshot.comp;
            let is_todo = itip_component.component_type == ICalendarComponentType::VTodo;
            let (remove_parameters, add_parameters) =
                reply_parameters(attendee, updated_attendee, itip_snapshot);
            let mut attendee_entry = series.comp.entries[attendee.entry_id as usize].clone();
            attendee_entry
                .params
                .retain(|param| !remove_parameters.contains(&param.name));
            attendee_entry.params.extend(add_parameters);

            let mut entries = series
                .comp
                .entries
                .iter()
                .filter(|entry| {
                    matches!(
                        entry.name,
                        ICalendarProperty::Organizer
                            | ICalendarProperty::Uid
                            | ICalendarProperty::Sequence
                    )
                })
                .cloned()
                .chain([attendee_entry])
                .collect::<Vec<_>>();
            entries.extend(
                itip_component
                    .entries
                    .iter()
                    .filter(|entry| {
                        matches!(
                            entry.name,
                            ICalendarProperty::Dtstamp | ICalendarProperty::RecurrenceId
                        ) || (is_todo
                            && matches!(
                                entry.name,
                                ICalendarProperty::PercentComplete
                                    | ICalendarProperty::Status
                                    | ICalendarProperty::Completed
                            ))
                    })
                    .cloned(),
            );

            // Add the attendees the sender delegated to
            for delegated_to in &updated_attendee.delegated_to {
                if let Some(itip_delegated) = itip_snapshot.attendee_by_email(&delegated_to.email) {
                    entries.push(itip_component.entries[itip_delegated.entry_id as usize].clone());
                }
            }

            merge_actions.push(MergeAction::AddComponent {
                component: ICalendarComponent {
                    component_type: itip_component.component_type.clone(),
                    entries,
                    component_ids: vec![],
                },
            });
        } else {
            return Err(ItipError::SenderIsNotParticipant(sender.to_string()));
        }
    }

    Ok(())
}

fn reply_parameters(
    attendee: &Attendee<'_>,
    updated_attendee: &Attendee<'_>,
    itip_snapshot: &ItipSnapshot<'_>,
) -> (Vec<ICalendarParameterName>, Vec<ICalendarParameter>) {
    let mut add_parameters = Vec::new();
    let mut remove_parameters = Vec::new();
    if attendee.part_stat != updated_attendee.part_stat {
        remove_parameters.push(ICalendarParameterName::Partstat);
        if let Some(part_stat) = updated_attendee.part_stat {
            add_parameters.push(ICalendarParameter::partstat(part_stat.clone()));
        }
    }

    if attendee.rsvp != updated_attendee.rsvp {
        remove_parameters.push(ICalendarParameterName::Rsvp);
        if let Some(rsvp) = updated_attendee.rsvp {
            add_parameters.push(ICalendarParameter::rsvp(rsvp));
        }
    }

    if attendee.delegated_to != updated_attendee.delegated_to {
        remove_parameters.push(ICalendarParameterName::DelegatedTo);
        if !updated_attendee.delegated_to.is_empty() {
            add_parameters.extend(
                updated_attendee.delegated_to.iter().map(|email| {
                    ICalendarParameter::delegated_to(Uri::Location(email.to_string()))
                }),
            );
        }
    }

    // RFC 6638 3.2.5: the status defaults to 2.0 when the reply carries none
    remove_parameters.push(ICalendarParameterName::ScheduleStatus);
    add_parameters.push(ICalendarParameter::schedule_status(
        if !itip_snapshot.request_status.is_empty() {
            itip_snapshot.request_status.join(",")
        } else {
            "2.0".to_string()
        },
    ));

    (remove_parameters, add_parameters)
}

// The start times of a series on its own, without the instances that override it
fn series_occurrences(ical: &ICalendar, main_comp_id: u16, max_instances: usize) -> AHashSet<i64> {
    let mut series = ical.clone();
    let overrides = series
        .components
        .iter()
        .enumerate()
        .filter(|(comp_id, comp)| {
            comp.component_type.is_scheduling_object() && *comp_id != main_comp_id as usize
        })
        .map(|(comp_id, _)| comp_id as u32)
        .collect::<Vec<_>>();
    if !overrides.is_empty() {
        series.remove_component_ids(&overrides);
    }
    if has_oversized_rrule(&series) {
        return AHashSet::new();
    }

    series
        .expand_dates(Tz::Floating, max_instances)
        .events
        .into_iter()
        .map(|event| event.start.timestamp())
        .collect()
}

pub fn itip_merge_changes(ical: &mut ICalendar, itip: &ICalendar, changes: Vec<MergeAction>) {
    let mut remove_component_ids: Vec<u32> = Vec::new();
    for action in changes {
        match action {
            MergeAction::AddEntries {
                component_id,
                entries,
            } => {
                let component = &mut ical.components[component_id as usize];
                component.entries.extend(entries);
            }
            MergeAction::RemoveEntries {
                component_id,
                entries,
            } => {
                let component = &mut ical.components[component_id as usize];
                component
                    .entries
                    .retain(|entry| !entries.contains(&entry.name));
            }
            MergeAction::AddParameters {
                component_id,
                entry_id,
                parameters,
            } => {
                ical.components[component_id as usize].entries[entry_id as usize]
                    .params
                    .extend(parameters);
            }
            MergeAction::RemoveParameters {
                component_id,
                entry_id,
                parameters,
            } => {
                ical.components[component_id as usize].entries[entry_id as usize]
                    .params
                    .retain(|param| !parameters.contains(&param.name));
            }
            MergeAction::AddComponent { component } => {
                let comp_id = ical.components.len() as u32;
                if let Some(root) = ical
                    .components
                    .get_mut(0)
                    .filter(|c| c.component_type == ICalendarComponentType::VCalendar)
                {
                    root.component_ids.push(comp_id);
                    ical.components.push(component);
                }
            }
            MergeAction::RemoveComponent { component_id } => {
                remove_component_ids.push(component_id as u32);
            }
        }
    }

    if !remove_component_ids.is_empty() {
        ical.remove_component_ids(&remove_component_ids);
    }

    merge_timezones(ical, itip);
}

fn merge_timezones(ical: &mut ICalendar, itip: &ICalendar) {
    let Some(root) = ical
        .components
        .first()
        .filter(|root| root.component_type == ICalendarComponentType::VCalendar)
    else {
        return;
    };
    let mut insert_at = root
        .component_ids
        .iter()
        .position(|component_id| {
            ical.component_by_id(*component_id)
                .is_none_or(|comp| comp.component_type != ICalendarComponentType::VTimezone)
        })
        .unwrap_or(root.component_ids.len());

    let mut tz_ids = TimezoneIds::of(ical);
    for tz in itip.timezones() {
        let Some(tz_id) = timezone_id(tz) else {
            continue;
        };

        if !tz_ids.is_missing(tz_id) {
            continue;
        }
        tz_ids.defined.insert(tz_id.to_string());

        let tz_component_id = ical.components.len() as u32;
        ical.components.reserve(tz.component_ids.len() + 1);
        ical.components.push(ICalendarComponent {
            component_type: ICalendarComponentType::VTimezone,
            entries: tz.entries.clone(),
            component_ids: Vec::new(),
        });
        ical.components.extend(
            tz.component_ids
                .iter()
                .filter_map(|component_id| itip.component_by_id(*component_id))
                .map(|item| ICalendarComponent {
                    component_type: item.component_type.clone(),
                    entries: item.entries.clone(),
                    component_ids: Vec::new(),
                }),
        );
        let last_item_id = ical.components.len() as u32;
        if let Some(tz_component) = ical.components.get_mut(tz_component_id as usize) {
            tz_component.component_ids = (tz_component_id + 1..last_item_id).collect();
        }
        if let Some(root) = ical.components.first_mut() {
            root.component_ids.insert(insert_at, tz_component_id);
            insert_at += 1;
        }
    }

    ical.add_missing_timezones();
}

// inbuxa: the time zones a calendar defines and the ones it refers to,
// gathered in one pass. Looking a zone up by scanning the calendar again for
// every VTIMEZONE of an iTIP message took time in the product of their sizes.
struct TimezoneIds {
    defined: AHashSet<String>,
    referenced: AHashSet<String>,
}

impl TimezoneIds {
    fn of(ical: &ICalendar) -> Self {
        let mut ids = TimezoneIds {
            defined: AHashSet::new(),
            referenced: AHashSet::new(),
        };
        for component in &ical.components {
            if component.component_type == ICalendarComponentType::VTimezone {
                if let Some(tz_id) = timezone_id(component) {
                    ids.defined.insert(tz_id.to_string());
                }
            } else {
                ids.referenced.extend(
                    component
                        .entries
                        .iter()
                        .filter_map(|entry| entry.tz_id())
                        .map(str::to_string),
                );
            }
        }
        ids
    }

    // Whether the calendar refers to a time zone it has no definition for
    fn is_missing(&self, tz_id: &str) -> bool {
        self.referenced.contains(tz_id) && !self.defined.contains(tz_id)
    }
}

fn timezone_id(component: &ICalendarComponent) -> Option<&str> {
    component
        .property(&ICalendarProperty::Tzid)
        .and_then(|entry| entry.values.first())
        .and_then(|value| value.as_text())
}

pub fn itip_method(ical: &ICalendar) -> Result<&ICalendarMethod, ItipError> {
    ical.components
        .first()
        .and_then(|comp| {
            comp.entries.iter().find_map(|entry| {
                if entry.name == ICalendarProperty::Method {
                    entry.values.first().and_then(|value| {
                        if let ICalendarValue::Method(method) = value {
                            Some(method)
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            })
        })
        .ok_or(ItipError::MissingMethod)
}

#[cfg(test)]
mod tests {
    use super::itip_merge_changes;
    use calcard::icalendar::{ICalendar, ICalendarComponentType};
    use std::time::{Duration, Instant};

    fn timezone_ids(ical: &ICalendar) -> Vec<String> {
        ical.timezones()
            .filter_map(super::timezone_id)
            .map(str::to_string)
            .collect()
    }

    // inbuxa: copying an iTIP message's VTIMEZONEs onto the stored event takes
    // one pass over each, not a pass over the event for every one of them
    #[test]
    fn itip_timezone_copy_is_linear() {
        const ZONES: usize = 40_000;
        let mut stored = String::from("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n");
        let mut itip = String::from("BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\n");
        for i in 0..ZONES {
            stored.push_str(&format!("X-NOTE;TZID=Zone/N{i}:x\r\n"));
            itip.push_str(&format!(
                "BEGIN:VTIMEZONE\r\nTZID:Zone/N{i}\r\nBEGIN:STANDARD\r\n\
                 DTSTART:19700101T000000\r\nTZOFFSETFROM:+0000\r\nTZOFFSETTO:+0000\r\n\
                 END:STANDARD\r\nEND:VTIMEZONE\r\n"
            ));
        }
        stored.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
        // a zone the event doesn't use, and one sent twice, are not copied
        itip.push_str(concat!(
            "BEGIN:VTIMEZONE\r\nTZID:Zone/Unused\r\nEND:VTIMEZONE\r\n",
            "BEGIN:VTIMEZONE\r\nTZID:Zone/N0\r\nEND:VTIMEZONE\r\n",
            "BEGIN:VEVENT\r\nUID:x\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        ));
        let mut ical = ICalendar::parse(&stored).unwrap();
        let itip = ICalendar::parse(&itip).unwrap();

        let started = Instant::now();
        itip_merge_changes(&mut ical, &itip, vec![]);
        let elapsed = started.elapsed();

        let ids = timezone_ids(&ical);
        assert_eq!(ids.len(), ZONES);
        assert_eq!(ids.first().map(String::as_str), Some("Zone/N0"));
        assert_eq!(
            ids.last().map(String::as_str),
            Some(format!("Zone/N{}", ZONES - 1).as_str())
        );
        // every definition is ahead of the event, with its observance
        let root = &ical.components[0];
        let first_event = root
            .component_ids
            .iter()
            .position(|id| {
                ical.components[*id as usize].component_type == ICalendarComponentType::VEvent
            })
            .unwrap();
        assert_eq!(first_event, ZONES);
        assert!(ical.timezones().all(|tz| tz.component_ids.len() == 1));
        assert!(
            elapsed < Duration::from_secs(20),
            "copying {ZONES} zones took {elapsed:?}"
        );
    }

    #[test]
    fn itip_timezone_copy_keeps_existing_definitions() {
        let mut ical = ICalendar::parse(concat!(
            "BEGIN:VCALENDAR\r\n",
            "BEGIN:VTIMEZONE\r\nTZID:Zone/Kept\r\nEND:VTIMEZONE\r\n",
            "BEGIN:VEVENT\r\nUID:x\r\nDTSTART;TZID=Zone/Kept:20260101T100000\r\n",
            "DTEND;TZID=Zone/New:20260101T110000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        ))
        .unwrap();
        let itip = ICalendar::parse(concat!(
            "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\n",
            "BEGIN:VTIMEZONE\r\nTZID:Zone/Kept\r\nX-FROM:itip\r\nEND:VTIMEZONE\r\n",
            "BEGIN:VTIMEZONE\r\nTZID:Zone/New\r\nX-FROM:itip\r\nEND:VTIMEZONE\r\n",
            "BEGIN:VEVENT\r\nUID:x\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        ))
        .unwrap();
        itip_merge_changes(&mut ical, &itip, vec![]);
        assert_eq!(timezone_ids(&ical), ["Zone/Kept", "Zone/New"]);
        let text = ical.to_string();
        assert_eq!(text.matches("X-FROM:itip").count(), 1, "{text}");
    }
}
