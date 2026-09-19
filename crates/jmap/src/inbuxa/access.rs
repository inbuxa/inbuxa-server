/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Reaching another account's fork-managed objects.

use common::{Server, auth::AccessToken};
use registry::schema::enums::Permission;
use types::id::Id;

/// Who may manage an account's masks (ME-18, ME-19) or archive (UD-7). The account itself (or
/// a group it's in); at server level, a holder of `impersonate`; inside a
/// tenant, a holder of `sysAccountUpdate`, for accounts in its own tenant
/// only, `impersonate` or not.
pub async fn assert_can_manage(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
) -> trc::Result<()> {
    if access_token.is_account_id(account_id) {
        return Ok(());
    }
    let allowed = if let Some(tenant_id) = access_token.tenant_id() {
        let target = server.account(account_id).await?;
        target.id_tenant == Some(tenant_id)
            && (access_token.has_permission(Permission::SysAccountUpdate)
                || access_token.is_member(account_id))
    } else {
        access_token.is_member(account_id)
    };
    if allowed {
        Ok(())
    } else {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details(format!("You can't manage account {}", Id::from(account_id))))
    }
}
