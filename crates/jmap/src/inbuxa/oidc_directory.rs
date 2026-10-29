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
//!
//! A directory that checks opaque tokens by introspection names the client
//! ID and secret it calls the provider with.

use directory::backend::oidc::config::opaque_token_policy;
use jmap_proto::error::set::{SetError, SetErrorType};
use registry::{
    schema::{
        enums::OidcOpaqueTokens,
        prelude::Property,
        structs::{Directory, SecretKeyOptional},
    },
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

    if opaque_token_policy(directory) == OidcOpaqueTokens::Introspection {
        let mut missing = Vec::new();
        if directory.introspection_client_id.is_none() {
            missing.push(ValidationError::required(Property::IntrospectionClientId));
        }
        if matches!(
            directory.introspection_client_secret,
            SecretKeyOptional::None
        ) {
            missing.push(ValidationError::required(
                Property::IntrospectionClientSecret,
            ));
        }
        if !missing.is_empty() {
            return Err(SetError::new(SetErrorType::ValidationFailed)
                .with_validation_errors(missing)
                .with_description(
                    "Opaque tokens are checked at the introspection endpoint, which needs the \
                     client ID and secret this server signs in to the provider with.",
                ));
        }
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

    #[test]
    fn introspection_names_its_client() {
        let with = |policy: Option<OidcOpaqueTokens>, url: bool, client: bool| {
            Directory::Oidc(OidcDirectory {
                require_audience: Some("inbuxa".to_string()),
                opaque_tokens: policy,
                introspection_url: url.then(|| "https://idp.example.org/introspect".to_string()),
                introspection_client_id: client.then(|| "inbuxa".to_string()),
                introspection_client_secret: if client {
                    SecretKeyOptional::Value(registry::schema::structs::SecretKeyValue {
                        secret: "secret".to_string(),
                    })
                } else {
                    SecretKeyOptional::None
                },
                ..Default::default()
            })
        };

        assert!(validate(&with(None, false, false), None).is_ok());
        assert!(validate(&with(None, true, false), None).is_err());
        assert!(validate(&with(None, true, true), None).is_ok());
        assert!(
            validate(
                &with(Some(OidcOpaqueTokens::Introspection), false, false),
                None
            )
            .is_err()
        );
        assert!(
            validate(
                &with(Some(OidcOpaqueTokens::Introspection), false, true),
                None
            )
            .is_ok()
        );
        assert!(validate(&with(Some(OidcOpaqueTokens::Reject), true, false), None).is_ok());
        assert!(validate(&with(Some(OidcOpaqueTokens::Userinfo), false, false), None).is_ok());
    }
}
