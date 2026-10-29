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

    for tz in itip.timezones() {
        let Some(tz_id) = timezone_id(tz) else {
            continue;
        };

        let mut is_referenced = false;
        for component in &ical.components {
            if component.component_type == ICalendarComponentType::VTimezone {
                if timezone_id(component) == Some(tz_id) {
                    is_referenced = false;
                    break;
                }
            } else if !is_referenced {
                is_referenced = component
                    .entries
                    .iter()
                    .any(|entry| entry.tz_id() == Some(tz_id));
            }
        }
        if !is_referenced {
            continue;
        }

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
