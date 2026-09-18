/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Masked email over JMAP (`docs/spec/features/masked-email.md`): what both
//! APIs share, and upstream's `x:MaskedEmail` hooks. The rules themselves
//! are in `inbuxa_features::masked_email`.

use crate::{
    api::query::QueryResponseBuilder,
    registry::{
        mapping::{ObjectResponse, RegistryQueryResponse, RegistrySetResponse, ValidationResult},
        query::RegistryQueryFilters,
    },
};
use common::{Server, auth::AccessToken};
use inbuxa_features::masked_email::{
    State, address,
    ops::{self, Mask},
    policy,
};
use jmap_proto::{error::set::SetError, types::state::State as JmapState};
use registry::{
    jmap::JmapValue,
    schema::{
        enums::{Permission, StorageQuota},
        prelude::Property,
        structs::{MaskedEmail, Rate},
    },
    types::{datetime::UTCDateTime, duration::Duration},
};
use store::registry::RegistryFilterOp;
use trc::AddContext;
use types::id::Id;
use utils::map::vec_map::VecMap;

/// Why a mask can't be created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateRefusal {
    /// `emailPrefix` isn't 1 to 64 of `a-z0-9_` (acceptance test 7).
    InvalidPrefix,
    /// `emailDomain` isn't one the account is linked to (ME-12).
    DomainNotAllowed,
    /// `maxMaskedAddresses` is reached, or 0 (ME-14).
    OverQuota,
    /// Too many creates this hour (ME-15).
    RateLimited,
}

/// ME-18, ME-19: who may manage an account's masks. The account itself (or
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
        Err(trc::JmapEvent::Forbidden.into_err().details(format!(
            "You can't manage masked addresses of account {}",
            Id::from(account_id)
        )))
    }
}

/// The domains an account may have masks on, as (id, name): every domain
/// and alias domain it's linked to, its primary domain first (ME-12).
async fn domains_of(server: &Server, account_id: u32) -> trc::Result<Vec<(u32, String)>> {
    let account = server.account(account_id).await?;
    let mut domains: Vec<(u32, String)> = Vec::new();
    for address in account.addresses.iter() {
        if domains.iter().any(|(id, _)| *id == address.domain_id) {
            continue;
        }
        if let Some(domain) = server.domain_by_id(address.domain_id).await? {
            for name in domain.names.iter() {
                domains.push((address.domain_id, name.to_lowercase()));
            }
        }
    }
    Ok(domains)
}

/// Fills in a new mask's address, owner and creation time, after checking
/// the prefix, the domain and the account's limits (ME-12 to ME-16).
pub async fn prepare_create(
    server: &Server,
    account_id: u32,
    mask: &mut MaskedEmail,
    prefix: Option<&str>,
    domain: Option<&str>,
) -> trc::Result<Result<(), CreateRefusal>> {
    let prefix = prefix.filter(|p| !p.is_empty());
    if prefix.is_some_and(|p| !address::is_valid_prefix(p)) {
        return Ok(Err(CreateRefusal::InvalidPrefix));
    }

    let domains = domains_of(server, account_id).await?;
    let domain = match domain {
        Some(name) => domains
            .iter()
            .find(|(_, candidate)| candidate.eq_ignore_ascii_case(name.trim())),
        None => domains.first(),
    };
    let Some((domain_id, domain_name)) = domain.cloned() else {
        return Ok(Err(CreateRefusal::DomainNotAllowed));
    };

    let data = &server.core.storage.data;
    let account = server.account(account_id).await?;
    let limit = server.object_quota(
        account.quota_objects.as_deref(),
        StorageQuota::MaxMaskedAddresses,
    );
    if !policy::within_limit(
        limit,
        ops::live_count(data, server.registry(), account_id).await?,
    ) {
        return Ok(Err(CreateRefusal::OverQuota));
    }

    if let Some(per_hour) = policy::creates_per_hour()
        && server
            .in_memory_store()
            .is_rate_allowed(
                policy::KV_CREATE_RATE,
                &account_id.to_be_bytes(),
                &Rate {
                    count: per_hour,
                    period: Duration::from_millis(3_600_000),
                },
                false,
            )
            .await
            .caused_by(trc::location!())?
            .is_some()
    {
        return Ok(Err(CreateRefusal::RateLimited));
    }

    mask.email =
        address::generate(data, server.registry(), prefix, domain_id, &domain_name).await?;
    mask.account_id = Id::from(account_id);
    mask.created_at = UTCDateTime::now();
    Ok(Ok(()))
}

impl CreateRefusal {
    /// The refusal as a JMAP `SetError`, naming the property involved.
    pub fn into_set_error<P: jmap_tools::Property>(self, prefix: P, domain: P) -> SetError<P> {
        match self {
            CreateRefusal::InvalidPrefix => SetError::invalid_properties()
                .with_property(prefix)
                .with_description("emailPrefix must be 1 to 64 characters from a-z, 0-9 and _."),
            CreateRefusal::DomainNotAllowed => SetError::forbidden()
                .with_property(domain)
                .with_description("The account can't have masked addresses on this domain."),
            CreateRefusal::OverQuota => {
                SetError::new(jmap_proto::error::set::SetErrorType::OverQuota)
                    .with_description("The account's maxMaskedAddresses limit is reached.")
            }
            CreateRefusal::RateLimited => {
                SetError::new(jmap_proto::error::set::SetErrorType::RateLimit)
                    .with_description("Too many masked addresses created in the last hour.")
            }
        }
    }
}

/// `x:MaskedEmail/set`: a mask about to be created or changed (ME-12 to
/// ME-17). On an update, the server-set and create-only fields keep their
/// stored values.
pub(crate) async fn validate(
    set: &RegistrySetResponse<'_>,
    mask: &mut MaskedEmail,
    old: Option<&MaskedEmail>,
    unpatched: VecMap<Property, JmapValue<'_>>,
) -> ValidationResult {
    match old {
        None => {
            let text = |property| {
                unpatched
                    .get(&property)
                    .and_then(|value: &JmapValue<'_>| value.as_str())
                    .map(|value| value.to_string())
            };
            let prefix = text(Property::EmailPrefix);
            let domain = text(Property::EmailDomain);
            Ok(prepare_create(
                set.server,
                set.account_id,
                mask,
                prefix.as_deref(),
                domain.as_deref(),
            )
            .await?
            .map(|_| ObjectResponse::default())
            .map_err(|refusal| {
                refusal.into_set_error(Property::EmailPrefix, Property::EmailDomain)
            }))
        }
        Some(old) => {
            if mask.expires_at != old.expires_at {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(Property::ExpiresAt)
                    .with_description(
                        "expiresAt can only be set when the mask is created.",
                    )));
            }
            mask.email = old.email.clone();
            mask.account_id = old.account_id;
            mask.created_at = old.created_at;
            Ok(Ok(ObjectResponse::default()))
        }
    }
}

/// After `x:MaskedEmail/set` creates a mask: it starts `enabled`, or
/// `deleted` if created with `enabled: false` (ME-7a).
pub async fn created(server: &Server, id: Id, mask: &MaskedEmail) -> trc::Result<()> {
    ops::created(
        &server.core.storage.data,
        server.registry(),
        id,
        mask,
        State::from_upstream(mask.enabled),
    )
    .await
}

/// After `x:MaskedEmail/set` changes a mask: `enabled` sets the state
/// (ME-2), and anything else leaves it as it was.
pub async fn updated(
    server: &Server,
    id: Id,
    old: &MaskedEmail,
    new: &MaskedEmail,
) -> trc::Result<()> {
    let data = &server.core.storage.data;
    if let Some(mask) = ops::load(data, server.registry(), id).await? {
        let state = if old.enabled != new.enabled {
            State::from_upstream_write(new.enabled)
        } else {
            mask.state
        };
        ops::updated(data, server.registry(), &mask, state).await?;
    }
    Ok(())
}

/// After `x:MaskedEmail/set` destroys a mask: its address is tombstoned
/// (ME-3).
pub async fn destroyed(server: &Server, id: Id, mask: &MaskedEmail) -> trc::Result<()> {
    ops::destroyed(&server.core.storage.data, server.registry(), id, mask).await
}

/// `x:MaskedEmail/get`: `enabled` reports whether mail is accepted, so an
/// expired or deleted mask reads false (ME-6a). `false` when the mask is gone
/// (a pending one past its deadline, ME-8).
pub async fn read(server: &Server, id: Id, mask: &mut MaskedEmail) -> trc::Result<bool> {
    match ops::load(&server.core.storage.data, server.registry(), id).await? {
        Some(loaded) => {
            mask.enabled = loaded.state.as_upstream_enabled(loaded.expired);
            Ok(true)
        }
        None => Ok(false),
    }
}

/// `x:MaskedEmail/query`, which also filters on `enabled`, `forDomain` and
/// text in the address and description (a fork addition).
pub(crate) async fn query(mut req: RegistryQueryResponse<'_>) -> trc::Result<QueryResponseBuilder> {
    let account_id = req.request.account_id.document_id();
    assert_can_manage(req.server, req.access_token, account_id).await?;

    let mut enabled = None;
    let mut for_domain = None;
    let mut text = None;
    req.request
        .extract_filters(|property, op, value| match (property, op, value) {
            (Property::Enabled, RegistryFilterOp::Equal, serde_json::Value::Bool(v)) => {
                enabled = Some(v);
                true
            }
            (Property::ForDomain, RegistryFilterOp::Equal, serde_json::Value::String(v)) => {
                for_domain = Some(v);
                true
            }
            (Property::Text, _, serde_json::Value::String(v)) => {
                text = Some(v.to_lowercase());
                true
            }
            (Property::AccountId, _, _) => true,
            _ => false,
        })?;
    req.request
        .extract_parameters(req.server.core.jmap.query_max_results, Some(Property::Id))?;

    let mut ids = ops::of_account(
        &req.server.core.storage.data,
        req.server.registry(),
        account_id,
    )
    .await?
    .into_iter()
    .filter(|mask: &Mask| {
        enabled.is_none_or(|e| mask.state.as_upstream_enabled(mask.expired) == e)
            && for_domain
                .as_deref()
                .is_none_or(|d| mask.object.for_domain.as_deref() == Some(d))
            && text.as_deref().is_none_or(|t| {
                mask.object.email.to_lowercase().contains(t)
                    || mask
                        .object
                        .description
                        .as_deref()
                        .is_some_and(|d| d.to_lowercase().contains(t))
            })
    })
    .map(|mask| mask.id)
    .collect::<Vec<_>>();
    ids.sort_unstable();

    let mut response = QueryResponseBuilder::new(
        ids.len(),
        req.server.core.jmap.query_max_results,
        JmapState::Initial,
        &req.request,
    );
    for id in ids {
        if !response.add_id(id) {
            break;
        }
    }
    Ok(response)
}

/// The state of an account's masks, for `/get` and `/changes` (a fork
/// addition: upstream's `/get` has none).
pub async fn state(server: &Server, account_id: u32) -> trc::Result<JmapState> {
    let latest =
        inbuxa_features::masked_email::data::latest_change(&server.core.storage.data, account_id)
            .await?;
    Ok(if latest == 0 {
        JmapState::Initial
    } else {
        JmapState::Exact(latest)
    })
}

/// `x:MaskedEmail/changes` (a fork addition).
pub async fn changes(
    server: &Server,
    access_token: &AccessToken,
    request: jmap_proto::method::changes::ChangesRequest,
) -> trc::Result<jmap_proto::response::ResponseMethod<'static>> {
    use jmap_proto::{
        method::changes::ChangesResponse,
        response::{ChangesResponseMethod, ResponseMethod},
    };

    let account_id = request.account_id.document_id();
    assert_can_manage(server, access_token, account_id).await?;
    let since = match &request.since_state {
        JmapState::Initial => 0,
        JmapState::Exact(change_id) => *change_id,
        JmapState::Intermediate(_) => {
            return Err(trc::JmapEvent::CannotCalculateChanges.into_err());
        }
    };
    let max = request
        .max_changes
        .filter(|max| *max != 0)
        .unwrap_or(usize::MAX)
        .min(server.core.jmap.changes_max_results);
    let entries = inbuxa_features::masked_email::data::changes_since(
        &server.core.storage.data,
        account_id,
        since,
    )
    .await?;
    let changes = ops::collapse(since, &entries, max);

    Ok(ResponseMethod::Changes(ChangesResponseMethod::Registry(
        Box::new(ChangesResponse {
            account_id: request.account_id,
            old_state: request.since_state,
            new_state: if changes.new_state == 0 {
                JmapState::Initial
            } else {
                JmapState::Exact(changes.new_state)
            },
            has_more_changes: changes.has_more,
            created: changes.created,
            updated: changes.updated,
            destroyed: changes.destroyed,
            updated_properties: None,
        }),
    )))
}
