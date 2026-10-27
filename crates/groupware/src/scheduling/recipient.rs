/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    calendar::EVENT_HIDE_ATTENDEES,
    scheduling::{ItipError, ItipMessage},
};
use calcard::icalendar::ICalendar;
use common::config::groupware::GroupwareConfig;
use split::RecipientSplit;

pub(crate) mod series;
mod split;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AttendeeVisibility {
    #[default]
    All,
    RecipientOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientPolicy {
    pub visibility: AttendeeVisibility,
    pub max_recipients: usize,
    pub max_instances: usize,
}

impl AttendeeVisibility {
    pub fn from_event_flags(flags: u16) -> Self {
        if flags & EVENT_HIDE_ATTENDEES != 0 {
            AttendeeVisibility::RecipientOnly
        } else {
            AttendeeVisibility::All
        }
    }
}

impl RecipientPolicy {
    pub fn new(config: &GroupwareConfig, event_flags: u16) -> Self {
        RecipientPolicy {
            visibility: AttendeeVisibility::from_event_flags(event_flags),
            max_recipients: config.itip_outbound_max_recipients,
            max_instances: config.max_ical_instances,
        }
    }
}

pub(crate) fn itip_messages_per_recipient(
    messages: Vec<ItipMessage<ICalendar>>,
    policy: RecipientPolicy,
) -> Result<Vec<ItipMessage<ICalendar>>, ItipError> {
    if messages
        .iter()
        .map(|message| message.to.len())
        .sum::<usize>()
        >= policy.max_recipients
    {
        return Err(ItipError::TooManyRecipients);
    }

    let mut result = Vec::with_capacity(messages.len());
    for message in messages {
        if message.from_organizer {
            RecipientSplit::split(message, policy, &mut result);
        } else {
            result.push(message);
        }
    }
    Ok(result)
}

