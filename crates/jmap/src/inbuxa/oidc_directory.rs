/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! What an external OpenID Connect directory must name before it is saved
//! (http-directory-services-13).
//!
//! A directory with no required audience accepts any token its provider
//! issued, to any application, so a new one must name the audience: one
//! made by `x:Directory/set`, made by changing another directory's type, or
//! made at setup. A directory saved before this rule keeps working without
//! one and logs a warning each time it loads; it can still be edited, but an
//! audience it has can't be removed. Requiring it of every directory is left
//! to a later release.

use jmap_proto::error::set::{SetError, SetErrorType};
use registry::{
    schema::{prelude::Property, structs::Directory},
    types::error::ValidationError,
};

/// `stored` is the directory as saved before this write, None for a new one.
pub fn validate(
    directory: &Directory,
    stored: Option<&Directory>,
) -> Result<(), SetError<Property>> {
    let Directory::Oidc(directory) = directory else {
        return Ok(());
    };
    let may_omit_audience = matches!(
        stored,
        Some(Directory::Oidc(stored)) if stored.require_audience.is_none()
    );
    if directory.require_audience.is_none() && !may_omit_audience {
        return Err(SetError::new(SetErrorType::ValidationFailed)
            .with_validation_errors(vec![ValidationError::required(Property::RequireAudience)])
            .with_description(
                "Set the required audience: the client ID or resource identifier registered \
                 for this server at the provider. Without it, tokens the provider issued to any \
                 other application would sign in.",
            ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry::schema::structs::{LdapDirectory, OidcDirectory};

    fn oidc(audience: Option<&str>) -> Directory {
        Directory::Oidc(OidcDirectory {
            require_audience: audience.map(str::to_string),
            ..Default::default()
        })
    }

    #[test]
    fn new_directories_name_their_audience() {
        let ldap = Directory::Ldap(LdapDirectory::default());

        // New, or made from a directory of another type
        assert!(validate(&oidc(None), None).is_err());
        assert!(validate(&oidc(None), Some(&ldap)).is_err());
        assert!(validate(&oidc(Some("inbuxa")), None).is_ok());
        assert!(validate(&ldap, None).is_ok());

        // Saved before the audience was required: still editable without one
        assert!(validate(&oidc(None), Some(&oidc(None))).is_ok());
        // ... but an audience, once set, stays
        assert!(validate(&oidc(None), Some(&oidc(Some("inbuxa")))).is_err());
    }
}
