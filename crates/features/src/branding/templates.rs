/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Operator email templates and the RSVP page (BT-11 to BT-22). Templates
//! are read from the registry each time an email is rendered, so a change
//! takes effect at once (BT-18).

use registry::schema::structs::{CalendarAlarm, CalendarScheduling};
use std::{fmt::Debug, hash::Hash, str::FromStr};
use store::RegistryStore;
use types::id::Id;
use utils::template::{Template, TemplateItem};

/// The largest email template (BT-15).
pub const MAX_TEMPLATE_SIZE: usize = 256 * 1024;

/// The largest RSVP page (BT-22).
pub const MAX_PAGE_SIZE: usize = 1024 * 1024;

/// The variables the server sets, for either template (BT-13).
pub const VARIABLES: &[&str] = &[
    "page_title",
    "lang",
    "dir",
    "logo_cid",
    "header",
    "color",
    "event_title",
    "event_description",
    "event_details",
    "key",
    "value",
    "link",
    "changed",
    "old_value",
    "attendees_title",
    "attendees",
    "action_name",
    "action_url",
    "rsvp",
    "actions",
    "footer",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Block {
    If,
    Each,
}

/// A block token's kind and variable: `if name` or `each name`.
fn block<'x>(spec: &'x str, token: &str) -> Result<(Block, &'x str), String> {
    let spec = spec.trim();
    if let Some(name) = spec.strip_prefix("if ") {
        Ok((Block::If, name.trim()))
    } else if let Some(name) = spec.strip_prefix("each ") {
        Ok((Block::Each, name.trim()))
    } else {
        Err(format!("Unknown block {{{{{token}}}}}."))
    }
}

/// Walks a template's tokens as BT-12 defines the language. `allow_raw`
/// lets `{{!name}}` through, for stored templates (BT-14).
fn walk(template: &str, allow_raw: bool) -> Result<(), String> {
    let mut stack: Vec<(Block, &str)> = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let end = after.find("}}").ok_or("A {{ is never closed.")?;
        let token = &after[..end];
        if token.contains('\n') || token.contains('\r') {
            return Err(format!("A token spans lines: {{{{{}", token.trim()));
        }
        rest = &after[end + 2..];
        let token = token.trim();
        let name = if let Some(spec) = token.strip_prefix('#') {
            let (kind, name) = block(spec, token)?;
            if kind == Block::Each && stack.iter().any(|(k, _)| *k == Block::Each) {
                return Err(format!("{{{{#each {name}}}}} is inside another #each."));
            }
            stack.push((kind, name));
            name
        } else if let Some(spec) = token.strip_prefix('/') {
            let (kind, name) = block(spec, token)?;
            match stack.pop() {
                Some((open_kind, open_name)) if open_kind == kind && open_name == name => name,
                Some((_, open_name)) => {
                    return Err(format!(
                        "{{{{{token}}}}} doesn't close the open block {open_name}."
                    ));
                }
                None => return Err(format!("{{{{{token}}}}} closes no open block.")),
            }
        } else if let Some(name) = token.strip_prefix('!') {
            if !allow_raw {
                return Err(format!(
                    "{{{{{token}}}}}: raw output isn't allowed; values are always escaped."
                ));
            }
            name.trim()
        } else {
            token
        };
        if !VARIABLES.contains(&name) {
            return Err(format!("Unknown variable {name:?}."));
        }
    }
    match stack.last() {
        Some((_, name)) => Err(format!("The block {name} is never closed.")),
        None => Ok(()),
    }
}

/// Checks an alarm or iMIP template being written (BT-15).
pub fn check(template: &str) -> Result<(), String> {
    if template.len() > MAX_TEMPLATE_SIZE {
        return Err(format!(
            "The template is {} KiB; the limit is 256 KiB.",
            template.len().div_ceil(1024)
        ));
    }
    walk(template, false)
}

/// Checks an RSVP page being written (BT-22). Its content is the
/// operator's own; only its size is limited.
pub fn check_page(page: &str) -> Result<(), String> {
    if page.len() > MAX_PAGE_SIZE {
        Err(format!(
            "The page is {} KiB; the limit is 1 MiB.",
            page.len().div_ceil(1024)
        ))
    } else {
        Ok(())
    }
}

/// Parses a stored template for rendering: every value escaped, `{{!…}}`
/// included (BT-14).
pub fn parse<T: FromStr + Eq + Hash + Debug>(template: &str) -> Result<Template<T>, String> {
    walk(template, true)?;
    let mut parsed = Template::<T>::parse(template)?;
    for item in &mut parsed.items {
        if let TemplateItem::Variable { escape, .. } = item {
            *escape = true;
        }
    }
    Ok(parsed)
}

/// Which email template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which {
    /// `x:CalendarAlarm.template`.
    Alarm,
    /// `x:CalendarScheduling.emailTemplate`.
    Invite,
}

/// The stored template's text, if one is set.
pub async fn stored_text(registry: &RegistryStore, which: Which) -> trc::Result<Option<String>> {
    Ok(match which {
        Which::Alarm => registry
            .object::<CalendarAlarm>(Id::singleton())
            .await?
            .and_then(|o| o.template),
        Which::Invite => registry
            .object::<CalendarScheduling>(Id::singleton())
            .await?
            .and_then(|o| o.email_template),
    }
    .filter(|t| !t.trim().is_empty()))
}

/// The operator's template to render with, if one is set and parses
/// (BT-11). One that doesn't leaves the built-in in use (BT-19); the warning
/// comes from `warn_unusable`, at start and each settings reload.
pub async fn stored<T: FromStr + Eq + Hash + Debug>(
    registry: &RegistryStore,
    which: Which,
) -> trc::Result<Option<Template<T>>> {
    Ok(stored_text(registry, which)
        .await?
        .and_then(|text| parse(&text).ok()))
}

/// BT-19: a stored template that doesn't parse is reported, and the
/// built-in is used.
pub fn warn_unusable<T: FromStr + Eq + Hash + Debug>(field: &str, text: Option<&str>) {
    if let Some(text) = text.filter(|t| !t.trim().is_empty())
        && let Err(err) = parse::<T>(text)
    {
        trc::event!(
            Registry(trc::RegistryEvent::BuildWarning),
            Details = format!("{field} doesn't parse, so the built-in is used (BT-19): {err}")
        );
    }
}

/// The operator's RSVP page, if one is set (BT-20). Served byte for byte.
pub async fn rsvp_page(registry: &RegistryStore) -> trc::Result<Option<String>> {
    Ok(registry
        .object::<CalendarScheduling>(Id::singleton())
        .await?
        .and_then(|o| o.http_rsvp_template)
        .filter(|t| !t.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes() {
        assert!(check("<p>{{header}}</p>{{#each attendees}}{{key}}{{#if link}}x{{/if link}}{{/each attendees}}").is_ok());
        for (bad, why) in [
            ("{{#if header}}x", "never closed"),
            ("{{unknown}}", "Unknown variable"),
            ("{{!header}}", "raw output"),
            ("{{#each actions}}{{#each attendees}}{{/each attendees}}{{/each actions}}", "inside another"),
            ("{{/if header}}", "closes no open"),
            ("{{#if header}}{{/if footer}}", "doesn't close"),
            ("{{#if header}}{{/each header}}", "doesn't close"),
            ("{{hea\nder}}", "spans lines"),
            ("{{header", "never closed"),
        ] {
            let err = check(bad).unwrap_err();
            assert!(err.contains(why), "{bad}: {err}");
        }
        assert!(check(&"x".repeat(300 * 1024)).unwrap_err().contains("256 KiB"));
    }

    #[test]
    fn stored_raw_is_escaped() {
        let template = parse::<String>("{{!event_title}}|{{event_title}}").unwrap();
        let mut vars = utils::template::Variables::<String, String>::new();
        vars.insert_single("event_title".into(), "<b>x</b>".into());
        assert_eq!(template.eval(&vars), "&lt;b&gt;x&lt;/b&gt;|&lt;b&gt;x&lt;/b&gt;");
    }

    #[test]
    fn built_ins_use_only_known_variables() {
        for (name, text) in [
            (
                "alarm",
                include_str!("../../../../resources/html-templates/calendar-alarm.html"),
            ),
            (
                "invite",
                include_str!("../../../../resources/html-templates/calendar-invite.html"),
            ),
        ] {
            walk(text, true).unwrap_or_else(|err| panic!("{name}: {err}"));
        }
    }

    #[test]
    fn page_limit() {
        assert!(check_page("{{page_title}}").is_ok());
        assert!(check_page(&"x".repeat(MAX_PAGE_SIZE + 1)).is_err());
    }
}
