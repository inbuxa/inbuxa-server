/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Stored formats inbuxa changed.

use crate::{
    pickle::{Pickle, PickledStream},
    schema::{
        enums::{MtaRouteType, OidcOpaqueTokens},
        prelude::{ObjectImpl, ObjectInner, ObjectType},
        structs::{
            Bootstrap, Directory, DirectoryBootstrap, MtaRoute, MtaRouteCommon,
            MtaRouteInbuxaRelay, OidcDirectory,
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
    bootstrap.tracer.pickle(&mut bytes);
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
