/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! PATCH paths (RFC 7644 §3.5.2): `attrPath` or `valuePath [subAttr]`,
//! optionally prefixed by a schema URN.

use crate::{AttrPath, Filter, ScimError};

#[derive(Debug, Clone, PartialEq)]
pub struct PatchPath {
    /// The attribute, with its sub-attribute when written `name.sub`.
    pub attr: AttrPath,
    /// `attr[filter]`.
    pub filter: Option<Filter>,
    /// `attr[filter].sub`.
    pub sub_after_filter: Option<String>,
}

impl PatchPath {
    pub fn parse(text: &str) -> Result<PatchPath, ScimError> {
        let invalid = || ScimError::invalid_path(format!("'{text}' isn't a valid path"));
        let text = text.trim();
        let (head, filter, after) = match text.find('[') {
            Some(open) => {
                let close = text.rfind(']').filter(|close| *close > open).ok_or_else(invalid)?;
                let inner = &text[open + 1..close];
                let filter = Filter::parse(inner).map_err(|err| {
                    ScimError::invalid_path(format!("'{text}': {}", err.detail))
                })?;
                let after = &text[close + 1..];
                let after = if after.is_empty() {
                    None
                } else {
                    Some(after.strip_prefix('.').ok_or_else(invalid)?.to_string())
                };
                (&text[..open], Some(filter), after)
            }
            None => (text, None, None),
        };
        let attr = AttrPath::parse(head).ok_or_else(invalid)?;
        if filter.is_some() && attr.sub.is_some() {
            return Err(invalid());
        }
        Ok(PatchPath {
            attr,
            filter,
            sub_after_filter: after,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_paths() {
        let path = PatchPath::parse("displayName").unwrap();
        assert!(path.attr.is("displayname", None));
        assert!(path.filter.is_none());

        let path = PatchPath::parse("name.givenName").unwrap();
        assert!(path.attr.is("name", Some("givenName")));

        let path = PatchPath::parse("members[value eq \"2819c223\"]").unwrap();
        assert!(path.attr.is("members", None));
        assert!(path.filter.is_some());

        let path = PatchPath::parse("emails[type eq \"work\"].value").unwrap();
        assert_eq!(path.sub_after_filter.as_deref(), Some("value"));

        let path = PatchPath::parse(
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
        )
        .unwrap();
        assert_eq!(
            path.attr.urn.as_deref(),
            Some("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")
        );
        assert!(path.attr.is("department", None));
    }

    #[test]
    fn refuses_bad_paths() {
        for text in ["", "members[", "members[value eq]", "a[b eq 1]x", "1a", "a.b[c eq 1]"] {
            assert!(PatchPath::parse(text).is_err(), "{text}");
        }
    }
}
