/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Stored formats inbuxa changed.

use crate::{
    pickle::{Pickle, PickledStream},
    schema::{
        enums::{LogFormat, MtaRouteType, OidcOpaqueTokens},
        prelude::{ObjectImpl, ObjectInner, ObjectType},
        structs::{
            Bootstrap, Directory, DirectoryBootstrap, Domain, Enterprise, MtaRoute, MtaRouteCommon,
            MtaRouteInbuxaRelay, OidcDirectory, SpamSettings, Tenant, Tracer, TracerLog,
        },
    },
    types::{EnumImpl, map::Map},
};

/// An OIDC directory as it was stored before the opaque-token fields.
fn pickle_without_opaque_tokens(directory: &OidcDirectory, out: &mut Vec<u8>) {
    directory.description.pickle(out);
    directory.issuer_url.pickle(out);
    directory.require_audience.pickle(out);
    directory.require_scopes.pickle(out);
    directory.claim_username.pickle(out);
    directory.username_domain.pickle(out);
    directory.claim_name.pickle(out);
    directory.claim_groups.pickle(out);
    directory.member_tenant_id.pickle(out);
}

/// A tracer as it was stored before a Log tracer had a format (#456).
fn pickle_tracer_before_format(tracer: &Tracer, out: &mut Vec<u8>) {
    match tracer {
        Tracer::Log(log) => {
            0u16.pickle(out);
            log.path.pickle(out);
            log.prefix.pickle(out);
            log.rotate.pickle(out);
            log.ansi.pickle(out);
            log.multiline.pickle(out);
            log.enable.pickle(out);
            log.level.pickle(out);
            log.lossy.pickle(out);
            log.events.pickle(out);
            log.events_policy.pickle(out);
        }
        other => other.pickle(out),
    }
}

fn read(object: ObjectType, bytes: &[u8]) -> ObjectInner {
    ObjectInner::unpickle(object, &mut PickledStream::new(bytes).unwrap()).unwrap()
}

// http-directory-services-13: a directory saved before the opaque-token
// policy existed keeps today's behavior (userinfo); a new one starts unset
#[test]
fn oidc_directories_saved_before_the_opaque_token_policy_keep_userinfo() {
    let saved = OidcDirectory {
        description: "Keycloak".to_string(),
        issuer_url: "https://sso.example.org/realms/example".to_string(),
        require_audience: Some("inbuxa".to_string()),
        ..Default::default()
    };
    let as_read = OidcDirectory {
        opaque_tokens: Some(OidcOpaqueTokens::Userinfo),
        ..saved.clone()
    };

    // x:Directory, version 0
    let mut bytes = vec![0u8];
    2u16.pickle(&mut bytes);
    pickle_without_opaque_tokens(&saved, &mut bytes);
    assert_eq!(
        read(ObjectType::Directory, &bytes),
        ObjectInner::Directory(Directory::Oidc(as_read.clone()))
    );

    // x:Bootstrap, version 1, where more fields follow the directory
    let bootstrap = Bootstrap {
        server_hostname: "mx.example.org".to_string(),
        directory: DirectoryBootstrap::Oidc(saved.clone()),
        ..Default::default()
    };
    let mut bytes = vec![1u8];
    bootstrap.server_hostname.pickle(&mut bytes);
    bootstrap.default_domain.pickle(&mut bytes);
    bootstrap.request_tls_certificate.pickle(&mut bytes);
    bootstrap.generate_dkim_keys.pickle(&mut bytes);
    bootstrap.data_store.pickle(&mut bytes);
    bootstrap.blob_store.pickle(&mut bytes);
    bootstrap.search_store.pickle(&mut bytes);
    bootstrap.in_memory_store.pickle(&mut bytes);
    3u16.pickle(&mut bytes);
    pickle_without_opaque_tokens(&saved, &mut bytes);
    pickle_tracer_before_format(&bootstrap.tracer, &mut bytes);
    bootstrap.dns_server.pickle(&mut bytes);
    assert_eq!(
        read(ObjectType::Bootstrap, &bytes),
        ObjectInner::Bootstrap(Bootstrap {
            directory: DirectoryBootstrap::Oidc(as_read),
            ..bootstrap.clone()
        })
    );

    // Saved now, unset or not, both read back as they were
    for directory in [
        saved.clone(),
        OidcDirectory {
            opaque_tokens: Some(OidcOpaqueTokens::Introspection),
            introspection_url: Some("https://sso.example.org/introspect".to_string()),
            introspection_client_id: Some("inbuxa".to_string()),
            ..saved.clone()
        },
    ] {
        let bootstrap = Bootstrap {
            directory: DirectoryBootstrap::Oidc(directory.clone()),
            ..bootstrap.clone()
        };
        let directory = Directory::Oidc(directory);
        assert_eq!(
            read(ObjectType::Directory, &directory.to_pickled_vec()),
            ObjectInner::Directory(directory)
        );
        assert_eq!(
            read(ObjectType::Bootstrap, &bootstrap.to_pickled_vec()),
            ObjectInner::Bootstrap(bootstrap)
        );
    }
}

// Relay spec, RL-24: the inbuxaRelay route is a fourth route type, stored
// after the three there were, which read as before
#[test]
fn inbuxa_relay_routes_are_stored_after_the_others() {
    let route = MtaRoute::InbuxaRelay(MtaRouteInbuxaRelay {
        relays: Map::new(vec!["east".to_string(), "west".to_string()]),
        name: "relays".to_string(),
        description: Some("Through the east and west relays".to_string()),
    });
    let bytes = route.to_pickled_vec();
    assert_eq!(
        read(ObjectType::MtaRoute, &bytes),
        ObjectInner::MtaRoute(route)
    );

    let local = MtaRoute::Local(MtaRouteCommon {
        name: "local".to_string(),
        description: None,
    });
    let mut bytes = vec![0u8];
    2u16.pickle(&mut bytes);
    "local".to_string().pickle(&mut bytes);
    None::<String>.pickle(&mut bytes);
    assert_eq!(local.to_pickled_vec(), bytes);
    assert_eq!(
        read(ObjectType::MtaRoute, &bytes),
        ObjectInner::MtaRoute(local)
    );

    assert_eq!(
        MtaRouteType::parse("InbuxaRelay"),
        Some(MtaRouteType::InbuxaRelay)
    );
    assert_eq!(MtaRouteType::from_id(3), Some(MtaRouteType::InbuxaRelay));
}

/// An object as it was stored at `version`, before its last field: today's
/// bytes with the version byte replaced and the unset field taken off the end.
fn without_last_field<T: ObjectImpl>(object: &T, version: u8) -> Vec<u8> {
    let mut unset = Vec::new();
    None::<String>.pickle(&mut unset);
    let mut bytes = object.to_pickled_vec();
    assert!(bytes.ends_with(&unset));
    bytes.truncate(bytes.len() - unset.len());
    bytes[0] = version;
    bytes
}

// branding BT-27: domains, tenants and the server-wide branding saved before
// the dark-mode logo read back without one; saved now, with it
#[test]
fn logos_saved_before_dark_mode_read_back_without_a_dark_logo() {
    let domain = Domain {
        name: "example.org".to_string(),
        logo: Some("https://example.org/logo.png".to_string()),
        allow_scim_provisioning: true,
        ..Default::default()
    };
    let tenant = Tenant {
        name: "t".to_string(),
        logo: Some("https://example.org/t.png".to_string()),
        ..Default::default()
    };
    let enterprise = Enterprise {
        logo_url: Some("https://example.org/server.png".to_string()),
        ..Default::default()
    };
    assert_eq!(
        read(ObjectType::Domain, &without_last_field(&domain, 1)),
        ObjectInner::Domain(domain.clone())
    );
    assert_eq!(
        read(ObjectType::Tenant, &without_last_field(&tenant, 0)),
        ObjectInner::Tenant(tenant.clone())
    );
    assert_eq!(
        read(ObjectType::Enterprise, &without_last_field(&enterprise, 0)),
        ObjectInner::Enterprise(enterprise.clone())
    );

    let dark = Some("https://example.org/dark.png".to_string());
    let domain = Domain {
        logo_dark: dark.clone(),
        ..domain
    };
    let tenant = Tenant {
        logo_dark: dark.clone(),
        ..tenant
    };
    let enterprise = Enterprise {
        logo_url_dark: dark,
        ..enterprise
    };
    assert_eq!(
        read(ObjectType::Domain, &domain.to_pickled_vec()),
        ObjectInner::Domain(domain)
    );
    assert_eq!(
        read(ObjectType::Tenant, &tenant.to_pickled_vec()),
        ObjectInner::Tenant(tenant)
    );
    assert_eq!(
        read(ObjectType::Enterprise, &enterprise.to_pickled_vec()),
        ObjectInner::Enterprise(enterprise)
    );
}

// #456: Log tracers saved before the format setting read back as text, in a
// tracer of their own and in the bootstrap, where more fields follow the
// tracer; saved now, a JSON one reads back as JSON
#[test]
fn log_tracers_saved_before_the_format_read_back_as_text() {
    let log = TracerLog {
        path: "/var/log/inbuxa".to_string(),
        prefix: "inbuxa.log".to_string(),
        ansi: false,
        ..Default::default()
    };
    assert_eq!(log.format, LogFormat::Text);
    let tracer = Tracer::Log(log.clone());

    // x:Tracer, version 0
    let mut bytes = vec![0u8];
    pickle_tracer_before_format(&tracer, &mut bytes);
    assert_eq!(
        read(ObjectType::Tracer, &bytes),
        ObjectInner::Tracer(tracer.clone())
    );

    // x:Bootstrap, version 2
    let bootstrap = Bootstrap {
        server_hostname: "mx.example.org".to_string(),
        tracer: tracer.clone(),
        ..Default::default()
    };
    let mut bytes = vec![2u8];
    bootstrap.server_hostname.pickle(&mut bytes);
    bootstrap.default_domain.pickle(&mut bytes);
    bootstrap.request_tls_certificate.pickle(&mut bytes);
    bootstrap.generate_dkim_keys.pickle(&mut bytes);
    bootstrap.data_store.pickle(&mut bytes);
    bootstrap.blob_store.pickle(&mut bytes);
    bootstrap.search_store.pickle(&mut bytes);
    bootstrap.in_memory_store.pickle(&mut bytes);
    bootstrap.directory.pickle(&mut bytes);
    pickle_tracer_before_format(&bootstrap.tracer, &mut bytes);
    bootstrap.dns_server.pickle(&mut bytes);
    assert_eq!(
        read(ObjectType::Bootstrap, &bytes),
        ObjectInner::Bootstrap(bootstrap.clone())
    );

    // Saved now
    let tracer = Tracer::Log(TracerLog {
        format: LogFormat::Json,
        ..log
    });
    let bootstrap = Bootstrap {
        tracer: tracer.clone(),
        ..bootstrap
    };
    assert_eq!(
        read(ObjectType::Tracer, &tracer.to_pickled_vec()),
        ObjectInner::Tracer(tracer)
    );
    assert_eq!(
        read(ObjectType::Bootstrap, &bootstrap.to_pickled_vec()),
        ObjectInner::Bootstrap(bootstrap)
    );
}

// #401: spam settings saved before scanQrCodes read back with it off; saved
// now, with it
#[test]
fn spam_settings_saved_before_qr_codes_read_back_with_scanning_off() {
    let settings = SpamSettings {
        trust_contacts: false,
        spam_filter_rules_url: Some("https://example.org/rules.json.gz".to_string()),
        ..Default::default()
    };
    let mut unset = Vec::new();
    false.pickle(&mut unset);
    let mut old = settings.to_pickled_vec();
    assert!(old.ends_with(&unset));
    old.truncate(old.len() - unset.len());
    old[0] = 0;
    assert_eq!(
        read(ObjectType::SpamSettings, &old),
        ObjectInner::SpamSettings(settings.clone())
    );

    let settings = SpamSettings {
        scan_qr_codes: true,
        ..settings
    };
    assert_eq!(
        read(ObjectType::SpamSettings, &settings.to_pickled_vec()),
        ObjectInner::SpamSettings(settings)
    );
}
