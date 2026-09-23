/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Multi-tenancy acceptance tests 1 to 14, from
//! `docs/spec/features/multi-tenancy.md`. Each check names the test number
//! or the requirement it covers.
//!
//! Test 15, INBUXA's own data, is `tenant_compat` below. It needs a copy of
//! production data and is ignored until one is provided.

use crate::utils::{
    account::Account,
    jmap::JmapUtils,
    server::{TestServer, TestServerBuilder},
    smtp::SmtpConnection,
};
use common::auth::BuildAccessToken;
use email::mailbox::INBOX_ID;
use jmap_proto::error::set::SetErrorType;
use registry::{
    schema::{
        enums::{
            Permission, TaskStoreMaintenanceType, TaskTenantMaintenanceType, TenantStorageQuota,
        },
        prelude::{ObjectType, Property},
        structs::{
            self, CertificateManagement, CustomRoles, DkimManagement, DnsManagement, Domain,
            Expression, Imap, MtaStageAuth, Permissions, PermissionsList, Roles, Task, TaskStatus,
            TaskStoreMaintenance, TaskTenantMaintenance, Tenant, UserRoles,
        },
    },
    types::{EnumImpl, map::Map},
};
use serde_json::{Value, json};
use std::str::FromStr;
use store::write::{BatchBuilder, ValueClass};
use trc::{Collector, MetricType};
use types::id::Id;
use utils::map::vec_map::VecMap;

const SECRET_T_ADMIN: &str = "tenant t administrator passphrase";
const SECRET_T_USER: &str = "tenant t ordinary user passphrase";
const SECRET_U_ADMIN: &str = "tenant u administrator passphrase";
const SECRET_U_USER: &str = "tenant u ordinary user passphrase";
const SECRET_P: &str = "tenant p people share this passphrase";
const SECRET_D: &str = "tenant d people share this passphrase";

pub async fn test(test: &mut TestServer) {
    println!("Running multi-tenancy tests...");
    let admin = test.account("admin@example.org");

    // Two tenants, each with a domain, an administrator and a user
    let t_id = admin.create_tenant("Tenant T").await;
    let u_id = admin.create_tenant("Tenant U").await;
    let t_domain = admin
        .create_tenant_domain("t.example.org", Some(t_id))
        .await;
    let u_domain = admin
        .create_tenant_domain("u.example.org", Some(u_id))
        .await;

    // Acceptance test 6: an account created on a tenant's domain without a
    // memberTenantId is in that tenant (MT-7)
    let t_admin = admin
        .create_user_account(
            "tadmin@t.example.org",
            SECRET_T_ADMIN,
            "T admin",
            &[],
            vec![],
        )
        .await;
    assert_eq!(admin.tenant_of(t_admin.id()).await, Some(t_id), "test 6");
    admin.make_tenant_admin(t_admin.id()).await;
    let t_user = admin
        .create_user_account("tuser@t.example.org", SECRET_T_USER, "T user", &[], vec![])
        .await;
    let u_admin = admin
        .create_user_account(
            "uadmin@u.example.org",
            SECRET_U_ADMIN,
            "U admin",
            &[],
            vec![],
        )
        .await;
    admin.make_tenant_admin(u_admin.id()).await;
    let u_user = admin
        .create_user_account("uuser@u.example.org", SECRET_U_USER, "U user", &[], vec![])
        .await;
    assert_eq!(admin.tenant_of(u_user.id()).await, Some(u_id), "test 6");

    // MT-7: a tenant other than the domain's is refused, naming the domain
    admin
        .registry_create_object_expect_err(structs::Account::User(structs::UserAccount {
            name: "misplaced".to_string(),
            domain_id: t_domain,
            member_tenant_id: Some(u_id),
            ..Default::default()
        }))
        .await
        .assert_type(SetErrorType::InvalidForeignKey);

    // Acceptance test 1: the tenant admin lists only its tenant's accounts
    let listed = t_admin.all_ids(ObjectType::Account).await;
    assert_eq!(
        sorted(listed),
        sorted(vec![t_admin.id(), t_user.id()]),
        "test 1"
    );
    let fetched = t_admin
        .registry_get_many(ObjectType::Account, Vec::<Id>::new())
        .await;
    assert_eq!(
        sorted(fetched.list().iter().map(|a| a.object_id()).collect()),
        sorted(vec![t_admin.id(), t_user.id()]),
        "test 1"
    );

    // MT-11: memberTenantId isn't returned inside a tenant
    for account in fetched.list() {
        assert!(
            account.get(Property::MemberTenantId.as_str()).is_none(),
            "MT-11: {account}"
        );
    }

    // Acceptance test 2: another tenant's account is notFound, not forbidden
    let response = t_admin
        .registry_get_many(ObjectType::Account, [u_user.id()])
        .await;
    assert!(response.list().is_empty(), "test 2");
    assert_eq!(
        response.not_found().collect::<Vec<_>>(),
        vec![u_user.id().to_string().as_str()],
        "test 2"
    );

    // MT-2: server-level objects are out of reach, and so is the admin's own
    // account on the server level
    for object_type in [ObjectType::NetworkListener, ObjectType::SystemSettings] {
        assert_eq!(
            t_admin
                .registry_get_many(object_type, Vec::<Id>::new())
                .await
                .method_response()
                .text_field("type"),
            "forbidden",
            "MT-2 {object_type:?}"
        );
    }
    let response = t_admin
        .registry_get_many(ObjectType::Domain, Vec::<Id>::new())
        .await;
    assert_eq!(
        response
            .list()
            .iter()
            .map(|d| d.object_id())
            .collect::<Vec<_>>(),
        vec![t_domain],
        "MT-1: domains"
    );

    // MT-12: the tenant admin reads its own tenant, and nothing else, and
    // can't change it
    let response = t_admin
        .registry_get_many(ObjectType::Tenant, Vec::<Id>::new())
        .await;
    assert_eq!(
        response
            .list()
            .iter()
            .map(|t| t.object_id())
            .collect::<Vec<_>>(),
        vec![t_id],
        "MT-12"
    );
    assert!(
        response.list()[0]
            .get(Property::UsedDiskQuota.as_str())
            .is_some(),
        "MT-12: usage"
    );
    assert_eq!(
        t_admin.all_ids(ObjectType::Tenant).await,
        vec![t_id],
        "MT-12 query"
    );
    assert_eq!(
        t_admin
            .registry_get_many(ObjectType::Tenant, [u_id])
            .await
            .not_found()
            .count(),
        1,
        "MT-12"
    );
    assert_eq!(
        t_admin
            .registry_update(ObjectType::Tenant, [(t_id, json!({"name": "Renamed"}))])
            .await
            .method_response()
            .text_field("type"),
        "forbidden",
        "MT-12"
    );

    // MT-11: what a tenant admin creates lands in its tenant
    let t_group = t_admin
        .create_group_account("tgroup@t.example.org", "T group", &[])
        .await;
    assert_eq!(admin.tenant_of(t_group.id()).await, Some(t_id), "MT-11");
    let u_group = admin
        .create_group_account("ugroup@u.example.org", "U group", &[])
        .await;

    // Acceptance test 3: no group membership across tenants (MT-3)
    t_admin
        .registry_update_object_expect_err(
            ObjectType::Account,
            t_user.id(),
            json!({ Property::MemberGroupIds: Map::new(vec![u_group.id()]) }),
        )
        .await
        .assert_type(SetErrorType::InvalidForeignKey);
    admin
        .registry_update_object_expect_err(
            ObjectType::Account,
            u_user.id(),
            json!({ Property::MemberGroupIds: Map::new(vec![t_group.id()]) }),
        )
        .await
        .assert_type(SetErrorType::InvalidForeignKey);
    t_admin
        .registry_update_object_expect_err(
            ObjectType::Account,
            u_user.id(),
            json!({ Property::MemberGroupIds: Map::new(vec![t_group.id()]) }),
        )
        .await
        .assert_type(SetErrorType::NotFound);
    // A server-level account can't join a tenant's group either
    admin
        .registry_update_object_expect_err(
            ObjectType::Account,
            admin.id(),
            json!({ Property::MemberGroupIds: Map::new(vec![t_group.id()]) }),
        )
        .await
        .assert_type(SetErrorType::InvalidForeignKey);
    // Within the tenant it works
    t_admin
        .registry_update_object(
            ObjectType::Account,
            t_user.id(),
            json!({ Property::MemberGroupIds: Map::new(vec![t_group.id()]) }),
        )
        .await;

    // Acceptance test 5: a tenant admin can't set memberTenantId (MT-6)
    t_admin
        .registry_update(
            ObjectType::Account,
            [(t_user.id(), json!({ Property::MemberTenantId: u_id }))],
        )
        .await
        .not_updated(&t_user.id().to_string());
    t_admin
        .registry_update(
            ObjectType::Account,
            [(t_user.id(), json!({ Property::MemberTenantId: null }))],
        )
        .await
        .not_updated(&t_user.id().to_string());
    t_admin
        .registry_update(
            ObjectType::Domain,
            [(t_domain, json!({ Property::MemberTenantId: null }))],
        )
        .await
        .not_updated(&t_domain.to_string());
    assert_eq!(admin.tenant_of(t_user.id()).await, Some(t_id), "test 5");

    // Acceptance test 4: mail between tenants is delivered (MT-4)
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "tuser@t.example.org",
        &["uuser@u.example.org"],
        concat!(
            "From: tuser@t.example.org\r\n",
            "To: uuser@u.example.org\r\n",
            "Subject: across tenants\r\n",
            "\r\n",
            "Hello from tenant T.\r\n"
        ),
    )
    .await;
    assert!(
        test.server
            .get_used_quota_account(u_user.id().document_id())
            .await
            .unwrap()
            > 0,
        "test 4"
    );

    // MT-3: no sharing across tenants, and a missing grantee answers the same.
    // U's user has an inbox now that mail reached it.
    for grantee in [t_user.id(), Id::new(987654)] {
        let response = u_user
            .jmap_method_call(
                "Mailbox/set",
                json!({
                    "accountId": u_user.id_string(),
                    "update": {
                        Id::from(INBOX_ID).to_string(): {
                            "shareWith": { grantee.to_string(): { "mayReadItems": true } }
                        }
                    }
                }),
            )
            .await;
        response
            .not_updated(&Id::from(INBOX_ID).to_string())
            .to_set_error()
            .assert_type(SetErrorType::InvalidForeignKey);
    }

    // MT-22: the logo that applies, domain before tenant
    assert_eq!(t_user.session_logo().await, Value::Null, "MT-22");
    admin
        .registry_update_object(
            ObjectType::Tenant,
            t_id,
            json!({ Property::Logo: "https://logo.example.org/tenant.png" }),
        )
        .await;
    assert_eq!(
        t_user.session_logo().await,
        json!("https://logo.example.org/tenant.png"),
        "MT-22"
    );
    admin
        .registry_update_object(
            ObjectType::Domain,
            t_domain,
            json!({ Property::Logo: "https://logo.example.org/domain.png" }),
        )
        .await;
    assert_eq!(
        t_user.session_logo().await,
        json!("https://logo.example.org/domain.png"),
        "MT-22"
    );
    assert_eq!(u_user.session_logo().await, Value::Null, "MT-22");

    // Acceptance test 7 and MT-8: moving domains
    admin
        .registry_update_object_expect_err(
            ObjectType::Domain,
            t_domain,
            json!({ Property::MemberTenantId: null }),
        )
        .await
        .assert_type(SetErrorType::InvalidProperties)
        .assert_properties(&[Property::MemberTenantId.as_str()]);
    admin
        .registry_update_object_expect_err(
            ObjectType::Domain,
            t_domain,
            json!({ Property::MemberTenantId: u_id }),
        )
        .await
        .assert_type(SetErrorType::InvalidProperties);
    assert_eq!(admin.tenant_of_domain(t_domain).await, Some(t_id), "test 7");

    // Moving a domain in carries its principals and DKIM keys (MT-8, MT-9)
    let m_domain = admin
        .registry_create_object(Domain {
            name: "m.example.org".to_string(),
            is_enabled: true,
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            ..Default::default()
        })
        .await;
    test.wait_for_tasks_skip_failures().await;
    let m_key = *admin
        .dkim_keys_of(m_domain)
        .await
        .first()
        .expect("MT-8: no DKIM keys generated");
    let m_user = admin
        .create_user_account("muser@m.example.org", SECRET_T_USER, "M user", &[], vec![])
        .await;
    assert_eq!(admin.tenant_of(m_user.id()).await, None);
    admin
        .registry_update_object(
            ObjectType::Domain,
            m_domain,
            json!({ Property::MemberTenantId: t_id }),
        )
        .await;
    assert_eq!(admin.tenant_of(m_user.id()).await, Some(t_id), "MT-8");
    assert_eq!(
        admin
            .tenant_of_object(ObjectType::DkimSignature, m_key)
            .await,
        Some(t_id),
        "MT-8"
    );
    // ... and out again only once its people are gone
    admin
        .registry_update_object_expect_err(
            ObjectType::Domain,
            m_domain,
            json!({ Property::MemberTenantId: null }),
        )
        .await
        .assert_type(SetErrorType::InvalidProperties);
    admin.destroy_account(m_user).await;
    test.wait_for_tasks().await;
    admin
        .registry_update_object(
            ObjectType::Domain,
            m_domain,
            json!({ Property::MemberTenantId: null }),
        )
        .await;
    assert_eq!(
        admin
            .tenant_of_object(ObjectType::DkimSignature, m_key)
            .await,
        None,
        "MT-8"
    );
    admin
        .registry_destroy(
            ObjectType::DkimSignature,
            admin.dkim_keys_of(m_domain).await,
        )
        .await;
    admin.registry_destroy(ObjectType::Domain, [m_domain]).await;

    // MT-9: generated DKIM keys take the domain's tenant
    let k_domain = admin
        .registry_create_object(Domain {
            name: "k.example.org".to_string(),
            is_enabled: true,
            member_tenant_id: Some(t_id),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            ..Default::default()
        })
        .await;
    test.wait_for_tasks_skip_failures().await;
    let keys = admin.dkim_keys_of(k_domain).await;
    assert!(!keys.is_empty(), "MT-9: no keys generated");
    for key in &keys {
        assert_eq!(
            admin
                .tenant_of_object(ObjectType::DkimSignature, *key)
                .await,
            Some(t_id),
            "MT-9"
        );
    }
    admin
        .registry_destroy(ObjectType::DkimSignature, keys)
        .await;
    admin.registry_destroy(ObjectType::Domain, [k_domain]).await;

    // Acceptance test 8: a tenant that's still referenced can't be deleted
    admin
        .registry_destroy_object_expect_err(ObjectType::Tenant, t_id)
        .await
        .assert_type(SetErrorType::ObjectIsLinked);

    // Tests 9 to 11 use a tenant of their own
    let p_id = admin.create_tenant("Tenant P").await;
    admin
        .create_tenant_domain("p.example.org", Some(p_id))
        .await;
    let p_admin = admin
        .create_user_account("padmin@p.example.org", SECRET_P, "P admin", &[], vec![])
        .await;
    admin.make_tenant_admin(p_admin.id()).await;
    let p_user = admin
        .create_user_account(
            "puser@p.example.org",
            SECRET_P,
            "P user",
            &[],
            vec![Permission::UnlimitedRequests],
        )
        .await;

    // Acceptance test 9: a permission the tenant lacks has no effect (MT-13)
    assert!(
        !test
            .permissions_of(p_user.id())
            .await
            .has_permission(Permission::UnlimitedRequests),
        "test 9"
    );
    let s_user = admin
        .create_user_account(
            "suser@example.org",
            SECRET_P,
            "Server-level user",
            &[],
            vec![Permission::UnlimitedRequests],
        )
        .await;
    assert!(
        test.permissions_of(s_user.id())
            .await
            .has_permission(Permission::UnlimitedRequests),
        "test 9, outside a tenant"
    );

    // MT-15: impersonate has no effect in a tenant, even when the tenant
    // allows it and the user holds it
    admin
        .registry_update_object(
            ObjectType::Tenant,
            p_id,
            json!({
                Property::Permissions: Permissions::Merge(PermissionsList {
                    enabled_permissions: Map::new(vec![Permission::Impersonate]),
                    disabled_permissions: Map::default(),
                })
            }),
        )
        .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            p_user.id(),
            json!({
                Property::Permissions: Permissions::Merge(PermissionsList {
                    enabled_permissions: Map::new(vec![Permission::Impersonate]),
                    disabled_permissions: Map::default(),
                })
            }),
        )
        .await;
    assert!(
        !test
            .permissions_of(p_user.id())
            .await
            .has_permission(Permission::Impersonate),
        "MT-15: impersonate"
    );
    assert_eq!(
        p_user
            .jmap_method_call(
                "Mailbox/get",
                json!({ "accountId": admin.id_string(), "ids": null }),
            )
            .await
            .method_response()
            .text_field("type"),
        "forbidden",
        "MT-1: no reach into another account's mail"
    );
    admin
        .registry_update_object(
            ObjectType::Tenant,
            p_id,
            json!({ Property::Permissions: Permissions::Inherit }),
        )
        .await;

    // Acceptance test 10: disabled wins over enabled in Replace (MT-14)
    admin
        .registry_update_object(
            ObjectType::Tenant,
            p_id,
            json!({
                Property::Permissions: Permissions::Replace(PermissionsList {
                    enabled_permissions: Map::new(vec![
                        Permission::Authenticate,
                        Permission::JmapEmailGet,
                    ]),
                    disabled_permissions: Map::new(vec![Permission::JmapEmailGet]),
                })
            }),
        )
        .await;
    let token = test.permissions_of(p_user.id()).await;
    assert!(token.has_permission(Permission::Authenticate), "test 10");
    assert!(!token.has_permission(Permission::JmapEmailGet), "test 10");
    assert!(!token.has_permission(Permission::JmapMailboxGet), "test 10");
    admin
        .registry_update_object(
            ObjectType::Tenant,
            p_id,
            json!({ Property::Permissions: Permissions::Inherit }),
        )
        .await;
    assert!(
        test.permissions_of(p_user.id())
            .await
            .has_permission(Permission::JmapEmailGet),
        "test 10"
    );

    // Acceptance test 11: lowering a tenant's roles reaches a signed-in
    // administrator on its next request (MT-16)
    assert!(p_admin.can_list_accounts().await, "test 11");
    let user_role = admin.role_id("user").await;
    admin
        .registry_update_object(
            ObjectType::Tenant,
            p_id,
            json!({ Property::Roles: Roles::Custom(CustomRoles { role_ids: Map::new(vec![user_role]) }) }),
        )
        .await;
    assert!(!p_admin.can_list_accounts().await, "test 11: roles");
    admin
        .registry_update_object(
            ObjectType::Tenant,
            p_id,
            json!({ Property::Roles: Roles::Default }),
        )
        .await;
    assert!(p_admin.can_list_accounts().await, "test 11: restored");
    // The permissions field on its own too
    admin
        .registry_update_object(
            ObjectType::Tenant,
            p_id,
            json!({
                Property::Permissions: Permissions::Merge(PermissionsList {
                    enabled_permissions: Map::default(),
                    disabled_permissions: Map::new(vec![Permission::SysAccountQuery]),
                })
            }),
        )
        .await;
    assert!(!p_admin.can_list_accounts().await, "test 11: permissions");
    admin
        .registry_update_object(
            ObjectType::Tenant,
            p_id,
            json!({ Property::Permissions: Permissions::Inherit }),
        )
        .await;
    assert!(p_admin.can_list_accounts().await, "test 11: restored");

    // Acceptance test 12: count limits (MT-17, MT-18)
    let q_id = admin.create_tenant("Tenant Q").await;
    let q_domain = admin
        .create_tenant_domain("q.example.org", Some(q_id))
        .await;
    admin
        .set_tenant_quota(q_id, TenantStorageQuota::MaxAccounts, 2)
        .await;
    let q1 = admin.create_plain_user("q1", q_domain).await;
    let q2 = admin.create_plain_user("q2", q_domain).await;
    let events = Collector::read_metric(MetricType::LimitTenantQuota);
    admin
        .registry_create_object_expect_err(structs::Account::User(structs::UserAccount {
            name: "q3".to_string(),
            domain_id: q_domain,
            ..Default::default()
        }))
        .await
        .assert_type(SetErrorType::OverQuota)
        .assert_description_contains("maxAccounts");
    assert!(
        Collector::read_metric(MetricType::LimitTenantQuota) > events,
        "test 12: limit.tenant-quota"
    );
    admin
        .set_tenant_quota(q_id, TenantStorageQuota::MaxAccounts, 1)
        .await;
    assert_eq!(
        admin
            .registry_get_many(ObjectType::Account, [q1, q2])
            .await
            .list()
            .len(),
        2,
        "test 12: existing accounts stay"
    );
    admin
        .registry_create_object_expect_err(structs::Account::User(structs::UserAccount {
            name: "q4".to_string(),
            domain_id: q_domain,
            ..Default::default()
        }))
        .await
        .assert_type(SetErrorType::OverQuota);
    // Moving a domain in counts what comes with it
    let n_domain = admin.create_tenant_domain("n.example.org", None).await;
    let n_user = admin.create_plain_user("n1", n_domain).await;
    admin
        .registry_update_object_expect_err(
            ObjectType::Domain,
            n_domain,
            json!({ Property::MemberTenantId: q_id }),
        )
        .await
        .assert_type(SetErrorType::OverQuota);
    admin
        .registry_destroy(ObjectType::Account, [n_user])
        .await
        .assert_destroyed(&[n_user]);
    test.wait_for_tasks().await;
    admin.registry_destroy(ObjectType::Domain, [n_domain]).await;

    // A domain's generated DKIM keys count before it's created (MT-17, MT-9)
    admin
        .set_tenant_quota(q_id, TenantStorageQuota::MaxDkimKeys, 1)
        .await;
    admin
        .registry_create_object_expect_err(Domain {
            name: "keys.example.org".to_string(),
            is_enabled: true,
            member_tenant_id: Some(q_id),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            ..Default::default()
        })
        .await
        .assert_type(SetErrorType::OverQuota)
        .assert_description_contains("maxDkimKeys");

    // Acceptance test 13: the tenant's disk limit bounds all its members
    // together (MT-19, MT-20)
    let d_id = admin.create_tenant("Tenant D").await;
    admin
        .create_tenant_domain("d.example.org", Some(d_id))
        .await;
    let d_admin = admin
        .create_user_account("dadmin@d.example.org", SECRET_D, "D admin", &[], vec![])
        .await;
    admin.make_tenant_admin(d_admin.id()).await;
    for name in ["d1@d.example.org", "d2@d.example.org", "d3@d.example.org"] {
        admin
            .create_user_account(name, SECRET_D, "D user", &[], vec![])
            .await;
    }
    let message = concat!(
        "From: someone@remote.example.org\r\n",
        "To: d@d.example.org\r\n",
        "Subject: filling the tenant\r\n",
        "\r\n",
        "0123456789012345678901234567890123456789012345678901234567890123456789\r\n"
    );
    lmtp.ingest("someone@remote.example.org", &["d1@d.example.org"], message)
        .await;
    let one = admin.tenant_usage(d_id).await;
    assert!(one > 0, "MT-20: usage moves on delivery");
    lmtp.ingest("someone@remote.example.org", &["d2@d.example.org"], message)
        .await;
    let two = admin.tenant_usage(d_id).await;
    assert!(two > one, "MT-20");
    // Room for half a message more: the next one doesn't fit (observed 2)
    admin
        .set_tenant_quota(
            d_id,
            TenantStorageQuota::MaxDiskQuota,
            (two + one / 2) as u64,
        )
        .await;
    // The message is accepted and queued, and local delivery refuses it
    // for now, so it waits in the queue (MT-19a)
    lmtp.ingest("someone@remote.example.org", &["d3@d.example.org"], message)
        .await;
    let mut reason = String::new();
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let queued = admin.all_ids(ObjectType::QueuedMessage).await;
        reason = admin
            .registry_get_many(ObjectType::QueuedMessage, queued)
            .await
            .list_array()
            .to_string();
        if reason.contains("Organization over quota") {
            break;
        }
    }
    assert!(
        reason.contains("Organization over quota"),
        "test 13: {reason}"
    );
    assert_eq!(admin.tenant_usage(d_id).await, two, "test 13");

    // MT-5: only the recipient's tenant administrator sees it in the queue
    assert_eq!(
        d_admin.all_ids(ObjectType::QueuedMessage).await.len(),
        1,
        "MT-5: the tenant's own"
    );
    assert!(
        t_admin.all_ids(ObjectType::QueuedMessage).await.is_empty(),
        "MT-5: nothing else"
    );
    let queued = admin.all_ids(ObjectType::QueuedMessage).await;
    assert!(
        t_admin
            .registry_get_many(ObjectType::QueuedMessage, queued.clone())
            .await
            .list()
            .is_empty(),
        "MT-5"
    );
    admin
        .registry_destroy(ObjectType::QueuedMessage, queued)
        .await;

    // Acceptance test 14: recalculateQuota restores a corrupted figure (MT-21)
    test.corrupt_tenant_usage(d_id, 123_456).await;
    assert_ne!(admin.tenant_usage(d_id).await, two);
    admin
        .registry_create_object(Task::TenantMaintenance(TaskTenantMaintenance {
            tenant_id: d_id,
            maintenance_type: TaskTenantMaintenanceType::RecalculateQuota,
            status: TaskStatus::now(),
        }))
        .await;
    test.wait_for_tasks().await;
    assert_eq!(admin.tenant_usage(d_id).await, two, "test 14");
    // ... and resetTenantQuotas, every tenant at once
    test.corrupt_tenant_usage(d_id, -777).await;
    admin
        .registry_create_object(Task::StoreMaintenance(TaskStoreMaintenance {
            maintenance_type: TaskStoreMaintenanceType::ResetTenantQuotas,
            shard_index: None,
            status: TaskStatus::now(),
        }))
        .await;
    test.wait_for_tasks().await;
    assert_eq!(admin.tenant_usage(d_id).await, two, "test 14");

    // Clean up, leaving the server as the other tests expect it
    for account in [
        t_admin, t_user, t_group, u_admin, u_user, u_group, p_admin, p_user, s_user, d_admin,
    ] {
        admin.destroy_account(account).await;
    }
    for name in ["d1", "d2", "d3"] {
        let id = admin.account_id_by_name(name).await;
        admin
            .registry_destroy(ObjectType::Account, [id])
            .await
            .assert_destroyed(&[id]);
    }
    admin
        .registry_destroy(ObjectType::Account, [q1, q2])
        .await
        .assert_destroyed(&[q1, q2]);
    test.wait_for_tasks().await;
    for domain in admin
        .registry_query_ids(
            ObjectType::Domain,
            Vec::<(&str, &str)>::new(),
            Vec::<&str>::new(),
        )
        .await
    {
        if admin.tenant_of_domain(domain).await.is_some() {
            admin
                .registry_destroy(ObjectType::Domain, [domain])
                .await
                .assert_destroyed(&[domain]);
        }
    }
    for tenant in [t_id, u_id, p_id, q_id, d_id] {
        admin
            .registry_destroy(ObjectType::Tenant, [tenant])
            .await
            .assert_destroyed(&[tenant]);
    }
    let _ = u_domain;
}

/// Acceptance test 15 (compat): INBUXA's existing tenants, their members and
/// quotas read back unchanged, and each tenant admin sees what it saw before.
///
/// Needs a copy of INBUXA's data, which isn't in the repository:
///
/// - `INBUXA_COMPAT_ADMIN`: `name:password` of a server-level administrator
///   in that data;
/// - `INBUXA_COMPAT_EXPECTED`: a JSON file recorded against the Enterprise
///   server before the move, shaped as
///   `{"tenants": {"<id>": {"name", "quotas", "members": [ids]}},
///     "tenantAdmins": {"<name>": {"password", "accounts": [ids],
///     "domains": [ids]}}}`;
///
/// and the data itself in place of the test store: run with `NO_INSERT=1`
/// and the store's `TMPDIR`/`STORE` pointing at the copy, so it isn't reset.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn tenant_compat() {
    let admin = std::env::var("INBUXA_COMPAT_ADMIN").expect("INBUXA_COMPAT_ADMIN");
    let expected: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("INBUXA_COMPAT_EXPECTED").expect("INBUXA_COMPAT_EXPECTED"))
            .expect("expected file"),
    )
    .expect("expected JSON");
    assert!(
        std::env::var("NO_INSERT").is_ok(),
        "NO_INSERT must be set, or the copy of inbuxa's data is wiped"
    );

    let test = TestServerBuilder::new("tenant_compat")
        .await
        .with_default_listeners()
        .await
        .build_with_opts(false)
        .await;
    let (name, secret) = admin.split_once(':').expect("name:password");
    let admin = Account::new(
        leak(name),
        leak(secret),
        &[],
        "Compat admin",
        Id::from(u32::MAX),
    );

    admin.assert_authenticates("INBUXA_COMPAT_ADMIN").await;

    // Tenants, their quotas and their members read back unchanged
    for (id, tenant) in expected["tenants"].as_object().expect("tenants") {
        let id = Id::from_str(id).expect("tenant id");
        let stored = admin.registry_get::<Tenant>(id).await;
        assert_eq!(stored.name, tenant["name"].as_str().unwrap(), "{id}");
        assert_eq!(
            serde_json::to_value(&stored.quotas).unwrap(),
            tenant["quotas"],
            "{id}"
        );
        let mut members = admin
            .registry_query_ids(
                ObjectType::Account,
                [(Property::MemberTenantId, id.to_string())],
                Vec::<&str>::new(),
            )
            .await;
        members.sort_unstable();
        assert_eq!(members, ids(&tenant["members"]), "tenant {id}'s members");
    }

    // Each tenant admin sees what it saw before
    for (name, seen) in expected["tenantAdmins"].as_object().expect("tenantAdmins") {
        let tenant_admin = Account::new(
            leak(name),
            leak(seen["password"].as_str().unwrap()),
            &[],
            "Tenant admin",
            Id::from(u32::MAX),
        );
        for (object_type, key) in [
            (ObjectType::Account, "accounts"),
            (ObjectType::Domain, "domains"),
        ] {
            let mut listed = tenant_admin.all_ids(object_type).await;
            listed.sort_unstable();
            assert_eq!(listed, ids(&seen[key]), "{name}'s {key}");
        }
    }
    drop(test);
}

fn ids(value: &Value) -> Vec<Id> {
    let mut ids = value
        .as_array()
        .unwrap()
        .iter()
        .map(|id| Id::from_str(id.as_str().unwrap()).unwrap())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids
}

fn leak(value: &str) -> &'static str {
    Box::leak(value.to_string().into_boxed_str())
}

/// Runs the tenancy tests alone, for working on them:
/// `cargo test -p tests tenant_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn tenant_tests() {
    let mut test = TestServerBuilder::new("tenant_tests")
        .await
        .with_default_listeners()
        .await
        .with_object(Imap {
            allow_plain_text_auth: true,
            ..Default::default()
        })
        .await
        .with_object(MtaStageAuth {
            require: Expression {
                else_: "false".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.org").await;
    test.insert_account(admin);
    self::test(&mut test).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}

fn sorted(mut ids: Vec<Id>) -> Vec<Id> {
    ids.sort_unstable();
    ids
}

impl TestServer {
    async fn permissions_of(&self, account_id: Id) -> common::auth::AccessToken {
        self.server
            .access_token(account_id.document_id())
            .await
            .unwrap()
            .build()
    }

    async fn corrupt_tenant_usage(&self, tenant_id: Id, by: i64) {
        let mut batch = BatchBuilder::new();
        batch.add(ValueClass::TenantQuota(tenant_id.document_id()), by);
        self.server
            .core
            .storage
            .data
            .write(batch.build_all())
            .await
            .unwrap();
    }
}

impl Account {
    async fn create_tenant(&self, name: &str) -> Id {
        self.registry_create_object(Tenant {
            name: name.to_string(),
            ..Default::default()
        })
        .await
    }

    async fn create_tenant_domain(&self, name: &str, tenant_id: Option<Id>) -> Id {
        self.registry_create_object(Domain {
            name: name.to_string(),
            is_enabled: true,
            member_tenant_id: tenant_id,
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        })
        .await
    }

    async fn dkim_keys_of(&self, domain_id: Id) -> Vec<Id> {
        self.registry_query_ids(
            ObjectType::DkimSignature,
            [(Property::DomainId, domain_id.to_string())],
            Vec::<&str>::new(),
        )
        .await
    }

    async fn create_plain_user(&self, name: &str, domain_id: Id) -> Id {
        self.registry_create_object(structs::Account::User(structs::UserAccount {
            name: name.to_string(),
            domain_id,
            ..Default::default()
        }))
        .await
    }

    async fn make_tenant_admin(&self, account_id: Id) {
        self.registry_update_object(
            ObjectType::Account,
            account_id,
            json!({ Property::Roles: UserRoles::Admin }),
        )
        .await;
    }

    async fn set_tenant_quota(&self, tenant_id: Id, quota: TenantStorageQuota, limit: u64) {
        self.registry_update_object(
            ObjectType::Tenant,
            tenant_id,
            json!({ Property::Quotas: VecMap::from_iter([(quota, limit)]) }),
        )
        .await;
    }

    async fn tenant_of(&self, account_id: Id) -> Option<Id> {
        self.tenant_of_object(ObjectType::Account, account_id).await
    }

    async fn tenant_of_domain(&self, domain_id: Id) -> Option<Id> {
        self.tenant_of_object(ObjectType::Domain, domain_id).await
    }

    async fn tenant_of_object(&self, object_type: ObjectType, id: Id) -> Option<Id> {
        let response = self.registry_get_many(object_type, [id]).await;
        let object = response
            .list()
            .first()
            .unwrap_or_else(|| panic!("{object_type:?} {id} not found: {response:?}"));
        object
            .get(Property::MemberTenantId.as_str())
            .and_then(|v| v.as_str())
            .map(|v| Id::from_str(v).unwrap())
    }

    async fn tenant_usage(&self, tenant_id: Id) -> i64 {
        self.registry_get_many(ObjectType::Tenant, [tenant_id])
            .await
            .list()[0]
            .integer_field(Property::UsedDiskQuota.as_str())
    }

    async fn role_id(&self, description: &str) -> Id {
        *self
            .registry_query_ids(
                ObjectType::Role,
                [(Property::Description, description)],
                Vec::<&str>::new(),
            )
            .await
            .first()
            .unwrap_or_else(|| panic!("Role {description} not found"))
    }

    async fn account_id_by_name(&self, name: &str) -> Id {
        *self
            .registry_query_ids(
                ObjectType::Account,
                [(Property::Name, name)],
                Vec::<&str>::new(),
            )
            .await
            .first()
            .unwrap_or_else(|| panic!("Account {name} not found"))
    }

    async fn all_ids(&self, object_type: ObjectType) -> Vec<Id> {
        self.registry_query_ids(object_type, Vec::<(&str, &str)>::new(), Vec::<&str>::new())
            .await
    }

    async fn can_list_accounts(&self) -> bool {
        let response = self
            .registry_query(
                ObjectType::Account,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new(),
            )
            .await;
        response.method_response().get("ids").is_some()
    }

    async fn session_logo(&self) -> Value {
        let session = self.jmap_session_object().await;
        session.0["accounts"][self.id_string()]["accountCapabilities"]["urn:inbuxa:jmap"]["logo"]
            .clone()
    }
}
