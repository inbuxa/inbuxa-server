/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:DataInventory/get` and `inbuxa:InventorySnapshot/get`: the
//! personal-data catalog evaluated against this server, and its history
//! (personal-data catalog spec, §6). Read-only, with `sysComplianceGet`.
//!
//! Inside a tenant both answer with the tenant's slice: tenant-scoped
//! sources only, and none of the server's processors, which describe the
//! whole server. The same holds for snapshots, which are taken of the whole
//! server and cut to the slice when read.

use common::{Server, auth::AccessToken};
use inbuxa_features::privacy::{Inventory, snapshot};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::{
        inbuxa_data_inventory::{DataInventory, DataInventoryProperty as P, DataInventoryValue},
        inbuxa_inventory_snapshot::{
            InventorySnapshot, InventorySnapshotProperty as S, InventorySnapshotValue,
        },
    },
};
use jmap_tools::{Element, Key, Map, Property, Value};
use std::borrow::Cow;
use types::{brand_version, id::Id};

fn json_to_value<Pr: Property, E: Element<Property = Pr>>(
    json: serde_json::Value,
) -> Value<'static, Pr, E> {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(b),
        serde_json::Value::Number(n) => {
            if let Some(n) = n.as_u64() {
                Value::Number(n.into())
            } else if let Some(n) = n.as_i64() {
                Value::Number(n.into())
            } else {
                Value::Number(n.as_f64().unwrap_or_default().into())
            }
        }
        serde_json::Value::String(s) => Value::Str(Cow::Owned(s)),
        serde_json::Value::Array(items) => {
            Value::Array(items.into_iter().map(json_to_value).collect())
        }
        serde_json::Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (key, value) in map {
                out.insert_unchecked(Key::Owned(key), json_to_value(value));
            }
            Value::Object(out)
        }
    }
}

fn to_json<T: serde::Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or_default()
}

fn utc(seconds: u64) -> String {
    jmap_proto::types::date::UTCDate::from_timestamp(seconds as i64).to_string()
}

/// A snapshot's inventory, cut to a tenant's slice when asked from one.
fn slice(mut inventory: Inventory, tenant_only: bool) -> Inventory {
    if tenant_only {
        inventory.items.retain(|item| item.scope == "tenant");
        inventory.processors.clear();
    }
    inventory
}

/// `inbuxa:DataInventory/get`.
pub async fn inventory_get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<DataInventory>,
) -> trc::Result<GetResponse<DataInventory>> {
    let properties = request.unwrap_properties(&[
        P::Id,
        P::EvaluatedAt,
        P::CatalogVersion,
        P::Summary,
        P::Items,
        P::Processors,
    ]);
    let (ids, not_found) = request.unwrap_ids(1)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let wanted = match ids {
        None => true,
        Some(ids) => {
            let mut wanted = false;
            for id in ids {
                if id.is_singleton() {
                    wanted = true;
                } else {
                    response.push_not_found(id);
                }
            }
            wanted
        }
    };
    if wanted {
        let inventory = server
            .data_inventory(access_token.tenant_id().is_some())
            .await?;
        let mut out = Map::with_capacity(properties.len());
        for property in &properties {
            let value = match property {
                P::Id => Value::Element(DataInventoryValue::Id(Id::singleton())),
                P::EvaluatedAt => Value::Str(utc(store::write::now()).into()),
                P::CatalogVersion => Value::Str(brand_version!().into()),
                P::Summary => json_to_value(to_json(&inventory.summary())),
                P::Items => json_to_value(to_json(&inventory.items)),
                P::Processors => json_to_value(to_json(&inventory.processors)),
            };
            out.insert_unchecked(Key::Property(property.clone()), value);
        }
        response.list.push(Value::Object(out));
    }
    Ok(response)
}

/// `inbuxa:InventorySnapshot/get`: by id (the time taken, as an id), or
/// `ids: null` for every snapshot kept, newest first. `inventory` is the
/// whole evaluated inventory; leave it out of `properties` for the list.
pub async fn snapshot_get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<InventorySnapshot>,
) -> trc::Result<GetResponse<InventorySnapshot>> {
    let tenant_only = access_token.tenant_id().is_some();
    let data = &server.core.storage.data;
    let properties =
        request.unwrap_properties(&[S::Id, S::TakenAt, S::Trigger, S::Summary, S::Inventory]);
    let times: Vec<u64> = match request.ids.take() {
        None => snapshot::list(data, 0, u64::MAX).await?,
        Some(_) => {
            let (ids, _) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
            ids.unwrap_or_default().into_iter().map(|id| id.id()).collect()
        }
    };
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found: vec![],
    };
    for taken_at in times {
        let Some(found) = snapshot::get(data, taken_at).await? else {
            response.push_not_found(Id::from(taken_at));
            continue;
        };
        let inventory = slice(found.inventory, tenant_only);
        let summary = if tenant_only { inventory.summary() } else { found.summary };
        let mut out = Map::with_capacity(properties.len());
        for property in &properties {
            let value = match property {
                S::Id => Value::Element(InventorySnapshotValue::Id(Id::from(taken_at))),
                S::TakenAt => Value::Str(utc(found.taken_at).into()),
                S::Trigger => json_to_value(to_json(&found.trigger)),
                S::Summary => json_to_value(to_json(&summary)),
                S::Inventory => json_to_value(to_json(&inventory)),
            };
            out.insert_unchecked(Key::Property(property.clone()), value);
        }
        response.list.push(Value::Object(out));
    }
    Ok(response)
}
