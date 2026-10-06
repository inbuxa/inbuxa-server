/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! What a registry write may set for a logo or template (BT-3, BT-15,
//! BT-22). Only a changed value is checked, so data from before the fork
//! never blocks an unrelated change (BT-4).

use crate::branding::{logo, templates};
use jmap_proto::error::set::SetError;
use registry::schema::prelude::{Object, ObjectInner, Property};

/// The logo and template fields an object carries, with their checks.
fn fields(inner: &ObjectInner) -> Vec<(Property, Option<&str>, fn(&str) -> Result<(), String>)> {
    match inner {
        ObjectInner::Enterprise(o) => vec![(Property::LogoUrl, o.logo_url.as_deref(), logo::check)],
        ObjectInner::Domain(o) => vec![(Property::Logo, o.logo.as_deref(), logo::check)],
        ObjectInner::Tenant(o) => vec![(Property::Logo, o.logo.as_deref(), logo::check)],
        ObjectInner::OAuthClient(o) => vec![(Property::Logo, o.logo.as_deref(), logo::check)],
        ObjectInner::CalendarAlarm(o) => {
            vec![(Property::Template, o.template.as_deref(), templates::check)]
        }
        ObjectInner::CalendarScheduling(o) => vec![
            (
                Property::EmailTemplate,
                o.email_template.as_deref(),
                templates::check,
            ),
            (
                Property::HttpRsvpTemplate,
                o.http_rsvp_template.as_deref(),
                templates::check_page,
            ),
        ],
        _ => vec![],
    }
}

/// Refuses a new or changed logo or template that breaks its rules, with
/// `invalidProperties` naming the field.
pub fn check(old: Option<&Object>, new: &Object) -> Result<(), SetError<Property>> {
    let before = old.map(|old| fields(&old.inner)).unwrap_or_default();
    for (property, value, check) in fields(&new.inner) {
        let Some(value) = value else { continue };
        let unchanged = before
            .iter()
            .any(|(p, v, _)| *p == property && *v == Some(value));
        if unchanged {
            continue;
        }
        if let Err(err) = check(value) {
            return Err(SetError::invalid_properties()
                .with_property(property)
                .with_description(err));
        }
    }
    Ok(())
}
