/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::utils::{jmap::JmapUtils, server::TestServer};
use ahash::AHashMap;
use common::auth::{BuildAccessToken, permissions::DefaultPermissions};
use jmap_proto::error::set::SetErrorType;
use registry::{
    schema::{
        enums::Permission,
        prelude::{ObjectType, Property},
        structs::{
            self, AccountSettings, Authentication, Credential, CustomRoles, PasswordCredential,
            Role, UserAccount, UserRoles,
        },
    },
    types::{EnumImpl, list::List, map::Map},
};
use serde_json::json;
use std::str::FromStr;
use types::id::Id;

pub async fn test(test: &mut TestServer) {
    println!("Running Authorization tests...");

    let admin = test.account("admin@example.org");
    let domain_id = admin.find_or_create_domain("example.org").await;

    // Create nested roles
    let l3_role_id = admin
        .registry_create_object(Role {
            description: "Level 3 role".to_string(),
            enabled_permissions: Map::new(vec![Permission::SysAccountSettingsGet]),
            ..Default::default()
        })
        .await;
    let l2_role_id = admin
        .registry_create_object(Role {
            description: "Level 2 role".to_string(),
            enabled_permissions: Map::new(vec![
                Permission::AuthenticateWithAlias,
                Permission::SysAccountSettingsUpdate,
            ]),
            role_ids: Map::new(vec![l3_role_id]),
            ..Default::default()
        })
        .await;
    let l1_role_id = admin
        .registry_create_object(Role {
            description: "Level 1 role".to_string(),
            enabled_permissions: Map::new(vec![Permission::Authenticate]),
            role_ids: Map::new(vec![l2_role_id]),
            ..Default::default()
        })
        .await;

    // Create a user with the nested role
    let user_id = admin
        .registry_create_object(structs::Account::User(UserAccount {
            name: "user".to_string(),
            domain_id,
            credentials: List::from_iter([Credential::Password(PasswordCredential {
                secret: "this is a very strong password".to_string(),
                ..Default::default()
            })]),
            roles: UserRoles::Custom(CustomRoles {
                role_ids: Map::new(vec![l1_role_id]),
            }),
            ..Default::default()
        }))
        .await;
    let user = crate::utils::account::Account::new(
        "user@example.org",
        "this is a very strong password",
        &[],
        "User",
        user_id,
    );

    // Verify user permissions include all permissions from the nested roles
    user.registry_update_object(
        ObjectType::AccountSettings,
        Id::singleton(),
        json!({
            Property::Description: "Updated description"
        }),
    )
    .await;
    assert_eq!(
        user.registry_get::<AccountSettings>(Id::singleton())
            .await
            .description
            .as_deref(),
        Some("Updated description")
    );

    // Remove read permissions from the l3 role and verify the user can no longer read account settings
    admin
        .registry_update_object(
            ObjectType::Role,
            l3_role_id,
            json!({
                Property::EnabledPermissions: {}
            }),
        )
        .await;
    assert_eq!(
        user.registry_get_many(ObjectType::AccountSettings, [Id::singleton()])
            .await
            .method_response()
            .text_field("type"),
        "forbidden"
    );

    // User should still be able to update account settings due to permissions from the l2 role
    user.registry_update_object(
        ObjectType::AccountSettings,
        Id::singleton(),
        json!({
            Property::Description: "Updated description v2"
        }),
    )
    .await;

    // Disable account settings update permission in the l3 role
    admin
        .registry_update_object(
            ObjectType::Role,
            l3_role_id,
            json!({
                Property::DisabledPermissions: Map::new(vec![Permission::SysAccountSettingsUpdate]),
            }),
        )
        .await;
    assert_eq!(
        user.registry_update(
            ObjectType::AccountSettings,
            [(
                Id::singleton(),
                json!({
                    Property::Description: "Updated description v3"
                })
            )]
        )
        .await
        .method_response()
        .text_field("type"),
        "forbidden"
    );

    // Assign user to the default user role
    admin
        .registry_update_object(
            ObjectType::Account,
            user_id,
            json!({
                Property::Roles: UserRoles::User
            }),
        )
        .await;

    // Make sure the user does not have any administrator permissions
    let permissions = DefaultPermissions::default();
    let mut num_permissions_verified = 0;
    let mut num_objects_verified = 0;
    let user_access_token = test
        .server
        .access_token(user_id.document_id())
        .await
        .unwrap()
        .build();
    for permission in permissions.superuser {
        if permissions.user.contains(&permission) {
            continue;
        }
        num_permissions_verified += 1;
        assert!(
            !user_access_token.has_permission(permission),
            "User should not have {:?} permission",
            permission
        );

        // inbuxa: the fork's own permissions (sysAuditGet) guard fork
        // methods, not registry objects; the audit suite checks those
        if let Some(name) = permission
            .as_str()
            .strip_prefix("sys")
            .and_then(|perm| perm.strip_suffix("Get"))
            && let Some(object_type) = ObjectType::parse(name)
        {
            assert_eq!(
                user.registry_get_many(object_type, Vec::<&str>::new())
                    .await
                    .method_response()
                    .text_field("type"),
                "forbidden",
                "User should not have permission to read {:?} objects",
                object_type
            );

            num_objects_verified += 1;
        }
    }
    assert_ne!(
        num_permissions_verified, 0,
        "No permissions were verified in the test"
    );
    assert_ne!(
        num_objects_verified, 0,
        "No object read permissions were verified in the test"
    );

    // An account on the default roles loses a permission at once when the
    // default user role drops it, though nothing links the account to the
    // role, and again when another role becomes the default
    let auth = admin.registry_get::<Authentication>(Id::singleton()).await;
    let default_role_id = auth.default_user_role_ids.as_slice()[0];
    let default_permissions = admin
        .registry_get::<Role>(default_role_id)
        .await
        .enabled_permissions
        .as_slice()
        .to_vec();
    assert!(default_permissions.contains(&Permission::SysAccountSettingsGet));
    let without_get = default_permissions
        .iter()
        .filter(|p| **p != Permission::SysAccountSettingsGet)
        .copied()
        .collect::<Vec<_>>();
    let as_map = |permissions: &[Permission]| {
        permissions
            .iter()
            .map(|p| (p.as_str().to_string(), serde_json::Value::Bool(true)))
            .collect::<serde_json::Map<String, serde_json::Value>>()
    };
    assert!(reads_settings(&user).await, "default role: before");
    admin
        .registry_update_object(
            ObjectType::Role,
            default_role_id,
            json!({ Property::EnabledPermissions: as_map(&without_get) }),
        )
        .await;
    assert!(
        !reads_settings(&user).await,
        "default role: a permission taken from it is gone at once"
    );
    admin
        .registry_update_object(
            ObjectType::Role,
            default_role_id,
            json!({ Property::EnabledPermissions: as_map(&default_permissions) }),
        )
        .await;
    assert!(reads_settings(&user).await, "default role: given back");
    let narrower_role_id = admin
        .registry_create_object(Role {
            description: "Narrower default".to_string(),
            enabled_permissions: Map::new(without_get),
            ..Default::default()
        })
        .await;
    admin
        .registry_update_object(
            ObjectType::Authentication,
            Id::singleton(),
            json!({ Property::DefaultUserRoleIds: Map::new(vec![narrower_role_id]) }),
        )
        .await;
    assert!(
        !reads_settings(&user).await,
        "default role: another default applies at once"
    );
    admin
        .registry_update_object(
            ObjectType::Authentication,
            Id::singleton(),
            json!({ Property::DefaultUserRoleIds: auth.default_user_role_ids }),
        )
        .await;
    assert!(reads_settings(&user).await, "default role: put back");
    admin
        .registry_destroy(ObjectType::Role, [narrower_role_id])
        .await
        .assert_destroyed(&[narrower_role_id]);

    // Deleting a linked role should not be allowed
    admin
        .registry_destroy_object_expect_err(ObjectType::Role, l2_role_id)
        .await
        .assert_type(SetErrorType::ObjectIsLinked);

    // Delete the account and roles in the correct order
    admin.destroy_account(user).await;
    for role_id in [l1_role_id, l2_role_id, l3_role_id] {
        admin
            .registry_destroy(ObjectType::Role, [role_id])
            .await
            .assert_destroyed(&[role_id]);
    }

    // Create test data for John and Jane
    let john = test
        .create_user_account(
            "admin@example.org",
            "john@example.org",
            "this is john's secret",
            &[],
            "john@example.org",
        )
        .await;
    let jane = test
        .create_user_account(
            "admin@example.org",
            "jane@example.org",
            "this is jane's secret",
            &[],
            "jane@example.org",
        )
        .await;
    let mut john_ids = AHashMap::new();
    let mut jane_ids = AHashMap::new();
    for (account, ids) in [(&john, &mut john_ids), (&jane, &mut jane_ids)] {
        let pk_id = account
            .registry_create_many(
                ObjectType::PublicKey,
                [json!({
                    Property::Description:"This is a public key",
                    Property::Key: SMIME_CERTIFICATE,
                })],
            )
            .await
            .created(0)
            .object_id();
        ids.insert(ObjectType::PublicKey, pk_id);

        let masked_id = account
            .registry_create_many(
                ObjectType::MaskedEmail,
                [json!({
                    Property::EmailDomain: "example.org",
                })],
            )
            .await
            .created(0)
            .object_id();
        ids.insert(ObjectType::MaskedEmail, masked_id);
    }

    // John should not be able to see Jane's objects and vice versa
    for (account, own_ids, other_ids) in
        [(&john, &john_ids, &jane_ids), (&jane, &jane_ids, &john_ids)]
    {
        for (object_type, id) in own_ids {
            assert_eq!(
                account
                    .registry_query(*object_type, Vec::<(&str, &str)>::new(), Vec::<&str>::new())
                    .await
                    .object_ids()
                    .collect::<Vec<_>>(),
                vec![*id]
            );
            assert_eq!(
                account
                    .registry_get_many(*object_type, Vec::<&str>::new())
                    .await
                    .list()
                    .len(),
                1
            );
        }

        for (object_type, id) in other_ids {
            assert_eq!(
                account
                    .registry_get_many(*object_type, [*id])
                    .await
                    .not_found()
                    .map(|id| Id::from_str(id).unwrap())
                    .collect::<Vec<_>>(),
                vec![*id]
            );

            account
                .registry_update_object_expect_err(
                    *object_type,
                    *id,
                    json!({
                        Property::Description: "Hacked description"
                    }),
                )
                .await
                .assert_type(SetErrorType::NotFound);

            account
                .registry_destroy_object_expect_err(*object_type, *id)
                .await
                .assert_type(SetErrorType::NotFound);
        }
    }

    // Admin should see all objects
    for object_type in [ObjectType::PublicKey, ObjectType::MaskedEmail] {
        let objects = admin
            .registry_query(object_type, Vec::<(&str, &str)>::new(), Vec::<&str>::new())
            .await
            .object_ids()
            .collect::<Vec<_>>();
        assert_eq!(objects.len(), 2);
        assert!(
            objects.contains(&john_ids[&object_type]) && objects.contains(&jane_ids[&object_type]),
        );

        // Filter by account id should work
        let objects = admin
            .registry_query(
                object_type,
                [(Property::AccountId, john.id().to_string())],
                Vec::<&str>::new(),
            )
            .await
            .object_ids()
            .collect::<Vec<_>>();
        assert_eq!(objects, vec![john_ids[&object_type]]);
    }

    // inbuxa: an administrator holding fewer permissions than an account used
    // to be able to change it (its password too) or delete it; permissions
    // were compared only when they were the thing being changed
    let limited_role_id = admin
        .registry_create_object(Role {
            description: "Limited administrator".to_string(),
            enabled_permissions: Map::new(vec![
                Permission::Authenticate,
                Permission::SysAccountGet,
                Permission::SysAccountQuery,
                Permission::SysAccountUpdate,
                Permission::SysAccountDestroy,
                Permission::SysRoleGet,
                Permission::SysRoleQuery,
                Permission::SysRoleCreate,
                Permission::SysRoleUpdate,
            ]),
            ..Default::default()
        })
        .await;
    let minion_role_id = admin
        .registry_create_object(Role {
            description: "Minion".to_string(),
            enabled_permissions: Map::new(vec![Permission::Authenticate]),
            ..Default::default()
        })
        .await;
    let mut account_ids = Vec::new();
    for (name, roles) in [
        (
            "limited",
            UserRoles::Custom(CustomRoles {
                role_ids: Map::new(vec![limited_role_id]),
            }),
        ),
        (
            "minion",
            UserRoles::Custom(CustomRoles {
                role_ids: Map::new(vec![minion_role_id]),
            }),
        ),
        ("boss", UserRoles::Admin),
    ] {
        account_ids.push(
            admin
                .registry_create_object(structs::Account::User(UserAccount {
                    name: name.to_string(),
                    domain_id,
                    credentials: List::from_iter([Credential::Password(PasswordCredential {
                        secret: "this is a very strong password".to_string(),
                        ..Default::default()
                    })]),
                    roles,
                    ..Default::default()
                }))
                .await,
        );
    }
    let (limited_id, minion_id, boss_id) = (account_ids[0], account_ids[1], account_ids[2]);
    let limited = crate::utils::account::Account::new(
        "limited@example.org",
        "this is a very strong password",
        &[],
        "Limited",
        limited_id,
    );
    // An account it outranks, it may change
    limited
        .registry_update_object(
            ObjectType::Account,
            minion_id,
            json!({ Property::Description: "Changed by a limited admin" }),
        )
        .await;
    // One that holds more, it may neither change nor delete
    limited
        .registry_update_object_expect_err(
            ObjectType::Account,
            boss_id,
            json!({ Property::Description: "Changed by a limited admin" }),
        )
        .await
        .assert_type(SetErrorType::Forbidden);
    limited
        .registry_destroy_object_expect_err(ObjectType::Account, boss_id)
        .await
        .assert_type(SetErrorType::Forbidden);

    // inbuxa: a role manager used to be able to make the administrator role a
    // parent of a role they hold, since only the role's own lists were checked
    let parent_role_ids = roles_bring_their_parents(test, &limited, limited_role_id).await;

    admin
        .registry_destroy(ObjectType::Account, account_ids.clone())
        .await
        .assert_destroyed(&account_ids);
    admin
        .registry_destroy(ObjectType::Role, [limited_role_id, minion_role_id])
        .await
        .assert_destroyed(&[limited_role_id, minion_role_id]);
    for role_id in parent_role_ids {
        admin
            .registry_destroy(ObjectType::Role, [role_id])
            .await
            .assert_destroyed(&[role_id]);
    }

    // Destroy test data
    for (account, ids) in [(&john, &john_ids), (&jane, &jane_ids)] {
        for (object_type, id) in ids {
            account
                .registry_destroy(*object_type, [*id])
                .await
                .assert_destroyed(&[*id]);
        }
    }
    admin.destroy_account(john).await;
    admin.destroy_account(jane).await;

    test.cleanup().await;
}

/// `manager` holds `manager_role_id`, which lets it manage roles and accounts
/// but not much else. Returns the roles it made, for the caller to remove
/// once `manager_role_id` is gone.
async fn roles_bring_their_parents(
    test: &TestServer,
    manager: &crate::utils::account::Account,
    manager_role_id: Id,
) -> Vec<Id> {
    let admin = test.account("admin@example.org");
    let manager_id = manager.id();
    let system_role_id = *admin
        .registry_query_ids(
            ObjectType::Role,
            [(Property::Description, "system")],
            Vec::<&str>::new(),
        )
        .await
        .first()
        .expect("system role");
    // Reaches the administrator role one step removed
    let middle_role_id = admin
        .registry_create_object(Role {
            description: "Middle".to_string(),
            role_ids: Map::new(vec![system_role_id]),
            ..Default::default()
        })
        .await;
    // Holds what the manager lacks, but turns it off again
    let muted_role_id = admin
        .registry_create_object(Role {
            description: "Muted".to_string(),
            enabled_permissions: Map::new(vec![
                Permission::Authenticate,
                Permission::SysTenantDestroy,
            ]),
            disabled_permissions: Map::new(vec![Permission::SysTenantDestroy]),
            ..Default::default()
        })
        .await;
    let signer_role_id = admin
        .registry_create_object(Role {
            description: "Signer".to_string(),
            enabled_permissions: Map::new(vec![Permission::Authenticate]),
            ..Default::default()
        })
        .await;

    // The administrator role as a parent of its own role, directly or one
    // step removed, or of a new role: refused
    for parent_id in [system_role_id, middle_role_id] {
        manager
            .registry_update_object_expect_err(
                ObjectType::Role,
                manager_role_id,
                json!({ Property::RoleIds: Map::new(vec![parent_id]) }),
            )
            .await
            .assert_type(SetErrorType::Forbidden);
    }
    manager
        .registry_create_object_expect_err(Role {
            description: "Back door".to_string(),
            role_ids: Map::new(vec![system_role_id]),
            ..Default::default()
        })
        .await
        .assert_type(SetErrorType::Forbidden);
    // Nor through its own account's roles
    manager
        .registry_update_object_expect_err(
            ObjectType::Account,
            manager_id,
            json!({
                Property::Roles: UserRoles::Custom(CustomRoles {
                    role_ids: Map::new(vec![manager_role_id, system_role_id]),
                })
            }),
        )
        .await
        .assert_type(SetErrorType::Forbidden);
    let token = test
        .server
        .access_token(manager_id.document_id())
        .await
        .unwrap()
        .build();
    assert!(!token.has_permission(Permission::SysTenantDestroy));

    // A parent bringing only what it holds, or what it turns off, is fine,
    // and so is a cycle back to the role being changed
    manager
        .registry_update_object(
            ObjectType::Role,
            manager_role_id,
            json!({ Property::RoleIds: Map::new(vec![signer_role_id, muted_role_id]) }),
        )
        .await;
    manager
        .registry_update_object(
            ObjectType::Role,
            signer_role_id,
            json!({ Property::RoleIds: Map::new(vec![manager_role_id]) }),
        )
        .await;
    // A parent that doesn't exist is a foreign key error, as before
    manager
        .registry_update_object_expect_err(
            ObjectType::Role,
            manager_role_id,
            json!({ Property::RoleIds: Map::new(vec![Id::from(999_999u64)]) }),
        )
        .await
        .assert_type(SetErrorType::InvalidForeignKey);

    // Break the cycle so the roles can go
    admin
        .registry_update_object(
            ObjectType::Role,
            signer_role_id,
            json!({ Property::RoleIds: Map::new(Vec::<Id>::new()) }),
        )
        .await;
    vec![signer_role_id, muted_role_id, middle_role_id]
}

/// Whether the account may read its own settings.
async fn reads_settings(account: &crate::utils::account::Account) -> bool {
    account
        .registry_get_many(ObjectType::AccountSettings, [Id::singleton()])
        .await
        .method_response()
        .get("type")
        .and_then(|t| t.as_str())
        != Some("forbidden")
}

const SMIME_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----
MIIDbjCCAlagAwIBAgIUZ4K0WXNSS8H0cUcZavD9EYqqTAswDQYJKoZIhvcNAQEN
BQAwLTErMCkGA1UEAxMiU2FtcGxlIExBTVBTIENlcnRpZmljYXRlIEF1dGhvcml0
eTAgFw0xOTExMjAwNjU0MThaGA8yMDUyMDkyNzA2NTQxOFowGTEXMBUGA1UEAxMO
QWxpY2UgTG92ZWxhY2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDD
7q35ZdG2JAzzJGNZDZ9sV7AKh0hlRfoFjTZN5m4RegQAYSyag43ouWi1xRN0avf0
UTYrwjK04qRdV7GzCACoEKq/xiNUOsjfJXzbCublN3fZMOXDshKKBqThlK75SjA9
Czxg7ejGoiY/iidk0e91neK30SCCaBTJlfR2ZDrPk73IPMeksxoTatfF9hw9dDA+
/Hi1yptN/aG0Q/s9icFrxr6y2zQXsjuQPmjMZgj10aD9cazWVgRYCgflhmA0V1uQ
l1wobYU8DAVxVn+GgabqyjGQMoythIK0Gn5+ofwxXXUM/zbU+g6+1ISdoXxRRFtq
2GzbIqkAHZZQm+BbnFrhAgMBAAGjgZcwgZQwDAYDVR0TAQH/BAIwADAeBgNVHREE
FzAVgRNhbGljZUBzbWltZS5leGFtcGxlMBMGA1UdJQQMMAoGCCsGAQUFBwMEMA8G
A1UdDwEB/wQFAwMHoAAwHQYDVR0OBBYEFKwuVFqk/VUYry7oZkQ40SXR1wB5MB8G
A1UdIwQYMBaAFLdSTXPAiD2yw3paDPOU9/eAonfbMA0GCSqGSIb3DQEBDQUAA4IB
AQB76o4Yz7yrVSFcpXqLrcGtdI4q93aKCXECCCzNQLp4yesh6brqaZHNJtwYcJ5T
qbUym9hJ70iJE4jGNN+yAZR1ltte0HFKYIBKM4EJumG++2hqbUaLz4tl06BHaQPC
v/9NiNY7q9R9c/B6s1YzHhwqkWht2a+AtgJ4BkpG+g+MmZMQV/Ao7RwLFKJ9OlMW
LBmEXFcpIJN0HpPasT0nEl/MmotSu+8RnClAi3yFfyTKb+8rD7VxuyXetqDZ6dU/
9/iqD/SZS7OQIjywtd343mACz3B1RlFxMHSA6dQAf2btGumqR0KiAp3KkYRAePoa
JqYkB7Zad06ngFl0G0FHON+7
-----END CERTIFICATE-----
";
