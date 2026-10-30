/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:RelayMessage` (docs/spec/features/relay.md, "Registry
//! objects"): what waits in each relay's `Inbound` and `Outbound` queues,
//! fetched over this node's link when asked, and never the message itself.
//! Destroying one discards held mail at the relay, or cancels an outbound
//! message: its recipients fail here, with no DSN, as a delivery cancelled
//! in this server's queue does, and the relay drops its copy (at its next
//! status, if it is sending it just then). The request layer records every
//! destroy in the audit log.

use super::relay::{json_to_value, server_level};
use common::{Server, auth::AccessToken};
use inbuxa_features::relay::{
    self as relays, Relay as StoredRelay,
    messages::{message_id, relay_of},
    outbound::{self, Handed, Linked},
};
use inbuxa_relay_proto::jmap::method;
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        query::{Filter as QueryFilter, QueryRequest, QueryResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_relay_message::{
        RelayMessage, RelayMessageFilter, RelayMessageProperty as P, RelayMessageValue,
    },
    request::IntoValid,
    types::state::State,
};
use jmap_tools::{Key, Map, Value};
use serde_json::json;
use smtp::outbound::relay::{Applied, RelayedStatus, apply_relayed};
use std::{collections::HashMap, sync::Arc};
use types::id::Id;

type RValue = Value<'static, P, RelayMessageValue>;

const ALL: &[P] = &[
    P::Id,
    P::RelayId,
    P::Direction,
    P::RelayMessageId,
    P::CreatedAt,
    P::Size,
    P::Envelope,
    P::State,
    P::ClaimedUntil,
    P::Session,
    P::DoorChecks,
    P::DeliveryStatus,
    P::NextAttemptAt,
    P::Attempts,
    P::ExpiresAt,
    P::QueueId,
];

/// The most ids one query returns.
const MAX_QUERY_LIMIT: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
        }
    }
}

/// One message at a relay, as the relay describes it.
struct Found {
    id: u64,
    relay_id: u32,
    direction: Direction,
    relay_message_id: String,
    created_at: String,
    object: serde_json::Value,
}

/// One relay's queues, read over this node's link.
struct Queues {
    linked: Arc<Linked>,
    messages: Vec<Found>,
    /// Its outbound messages' places in this server's queue.
    handed: HashMap<String, Handed>,
}

fn unavailable(relay: &StoredRelay, why: impl std::fmt::Display) -> trc::Error {
    trc::EventType::Relay(trc::RelayEvent::LinkDown)
        .into_err()
        .details(format!("Relay {}: {why}", relay.name))
        .ctx(trc::Key::Id, Id::from(relay.id).to_string())
}

async fn queues(server: &Server, relay: &StoredRelay) -> trc::Result<Queues> {
    let linked = server
        .inner
        .data
        .relay_senders
        .linked(relay.id)
        .ok_or_else(|| unavailable(relay, "this node has no link to it now"))?;
    let mut messages = Vec::new();
    for (direction, get) in [
        (Direction::Inbound, method::INBOUND_GET),
        (Direction::Outbound, method::OUTBOUND_GET),
    ] {
        let answer = linked
            .sender
            .call(get, json!({"ids": null}))
            .await
            .map_err(|why| unavailable(relay, why))?;
        for object in answer["list"].as_array().into_iter().flatten() {
            let Some(relay_message_id) = object["id"].as_str() else {
                continue;
            };
            let Some(id) = message_id(relay.id, relay_message_id) else {
                continue;
            };
            let created_at = match direction {
                Direction::Inbound => &object["receivedAt"],
                Direction::Outbound => &object["createdAt"],
            };
            messages.push(Found {
                id,
                relay_id: relay.id,
                direction,
                relay_message_id: relay_message_id.to_string(),
                created_at: created_at.as_str().unwrap_or_default().to_string(),
                object: object.clone(),
            });
        }
    }
    let handed = outbound::handed(server.store(), relay.id)
        .await?
        .into_iter()
        .map(|h| (h.id.clone(), h))
        .collect();
    Ok(Queues {
        linked,
        messages,
        handed,
    })
}

fn to_value(found: &Found, handed: &HashMap<String, Handed>, properties: &[P]) -> RValue {
    let field = |name: &str| -> RValue {
        match found.object.get(name) {
            Some(value) if !value.is_null() => json_to_value(value.clone()),
            _ => Value::Null,
        }
    };
    let inbound = found.direction == Direction::Inbound;
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(RelayMessageValue::Id(Id::new(found.id))),
            P::RelayId => Value::Element(RelayMessageValue::Id(Id::from(found.relay_id))),
            P::Direction => Value::Str(found.direction.as_str().into()),
            P::RelayMessageId => Value::Str(found.relay_message_id.clone().into()),
            P::CreatedAt => Value::Str(found.created_at.clone().into()),
            P::Size => field("size"),
            P::Envelope => field("envelope"),
            P::State if inbound => field("state"),
            P::ClaimedUntil if inbound => field("claimedUntil"),
            P::Session if inbound => field("session"),
            P::DoorChecks if inbound => field("doorChecks"),
            P::DeliveryStatus if !inbound => field("deliveryStatus"),
            P::NextAttemptAt if !inbound => field("nextAttemptAt"),
            P::Attempts if !inbound => field("attempts"),
            P::ExpiresAt if !inbound => field("expiresAt"),
            P::QueueId if !inbound => handed
                .get(&found.relay_message_id)
                .map_or(Value::Null, |h| {
                    Value::Element(RelayMessageValue::Id(Id::new(h.queue_id)))
                }),
            _ => Value::Null,
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// The relays with these messages, or every enabled relay.
fn wanted_relays(all: &[StoredRelay], ids: Option<&[Id]>) -> Vec<StoredRelay> {
    all.iter()
        .filter(|relay| match ids {
            Some(ids) => ids.iter().any(|id| relay_of(id.id()) == relay.id),
            None => relay.enabled,
        })
        .cloned()
        .collect()
}

pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<RelayMessage>,
) -> trc::Result<GetResponse<RelayMessage>> {
    server_level(access_token)?;
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let all = relays::all(server.store()).await?;
    let mut fetched = Vec::new();
    for relay in wanted_relays(&all, ids.as_deref()) {
        match queues(server, &relay).await {
            Ok(queues) => fetched.push(queues),
            // Asked for all: a relay this node can't reach now is left out
            Err(_) if ids.is_none() => {}
            Err(err) => return Err(err),
        }
    }
    match ids {
        None => {
            for queues in &fetched {
                for found in &queues.messages {
                    response
                        .list
                        .push(to_value(found, &queues.handed, &properties));
                }
            }
        }
        Some(ids) => {
            for id in ids {
                match fetched.iter().find_map(|queues| {
                    queues
                        .messages
                        .iter()
                        .find(|found| found.id == id.id())
                        .map(|found| (found, &queues.handed))
                }) {
                    Some((found, handed)) => {
                        response.list.push(to_value(found, handed, &properties))
                    }
                    None => response.push_not_found(id),
                }
            }
        }
    }
    Ok(response)
}

/// `inbuxa:RelayMessage/query`: newest first, of every enabled relay this
/// node is linked to, or of the one asked for, which must be.
pub async fn query(
    server: &Server,
    access_token: &AccessToken,
    request: QueryRequest<RelayMessage>,
) -> trc::Result<QueryResponse> {
    server_level(access_token)?;
    let unsupported = |why: String| trc::JmapEvent::UnsupportedFilter.into_err().details(why);
    let mut relay_id = None;
    let mut direction = None;
    for condition in request.filter {
        match condition {
            QueryFilter::Property(RelayMessageFilter::RelayId(id)) => relay_id = Some(id),
            QueryFilter::Property(RelayMessageFilter::Direction(d)) => {
                direction = Some(match d.as_str() {
                    "inbound" => Direction::Inbound,
                    "outbound" => Direction::Outbound,
                    _ => {
                        return Err(unsupported("direction is inbound or outbound.".to_string()));
                    }
                })
            }
            QueryFilter::Property(RelayMessageFilter::_T(other)) => {
                return Err(unsupported(format!("Unknown filter property {other}.")));
            }
            QueryFilter::And | QueryFilter::Close => {}
            QueryFilter::Or | QueryFilter::Not => {
                return Err(unsupported(
                    "Conditions must all hold; OR and NOT aren't supported.".to_string(),
                ));
            }
        }
    }
    let position = request.position.unwrap_or(0);
    if position < 0 || request.anchor.is_some() {
        return Err(unsupported(
            "Relay messages page by a position from the start.".to_string(),
        ));
    }
    let limit = request
        .limit
        .unwrap_or(MAX_QUERY_LIMIT)
        .min(MAX_QUERY_LIMIT);

    let all = relays::all(server.store()).await?;
    let mut found = Vec::new();
    match relay_id {
        Some(id) => {
            if let Some(relay) = all.iter().find(|r| u64::from(r.id) == id.id()) {
                found.extend(queues(server, relay).await?.messages);
            }
        }
        None => {
            for relay in all.iter().filter(|r| r.enabled) {
                if let Ok(queues) = queues(server, relay).await {
                    found.extend(queues.messages);
                }
            }
        }
    }
    found.retain(|f| direction.is_none_or(|d| f.direction == d));
    found.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
    let total = found.len();
    Ok(QueryResponse {
        account_id: request.account_id,
        query_state: State::Initial,
        can_calculate_changes: false,
        position,
        ids: found
            .into_iter()
            .skip(position as usize)
            .take(limit)
            .map(|f| Id::new(f.id))
            .collect(),
        total: request.calculate_total.unwrap_or(false).then_some(total),
        limit: Some(limit),
    })
}

/// What a relay's destroy did with one id.
enum Destroyed {
    Yes,
    /// It was gone already.
    NotFound,
    Refused(SetError<P>),
}

fn destroyed(answer: &serde_json::Value, id: &str) -> Destroyed {
    let Some(error) = answer["notDestroyed"].get(id) else {
        return Destroyed::Yes;
    };
    match error["type"].as_str() {
        Some("notFound") => Destroyed::NotFound,
        _ => Destroyed::Refused(
            SetError::forbidden().with_description(
                error["description"]
                    .as_str()
                    .unwrap_or("The relay refused.")
                    .to_string(),
            ),
        ),
    }
}

/// `inbuxa:RelayMessage/set`: destroy only.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, RelayMessage>,
) -> trc::Result<SetResponse<RelayMessage>> {
    server_level(access_token)?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    for (client_id, _) in request.unwrap_create() {
        response.not_created.append(
            client_id,
            SetError::forbidden().with_description("Only a relay makes its messages."),
        );
    }
    for (id, _) in request.unwrap_update().into_valid() {
        response.not_updated.append(
            id,
            SetError::forbidden()
                .with_description("A relay's message can't be changed, only destroyed."),
        );
    }

    let data = server.store();
    let all = relays::all(data).await?;
    let mut fetched: HashMap<u32, Queues> = HashMap::new();
    for id in request.unwrap_destroy().into_valid() {
        let Some(relay) = all.iter().find(|r| r.id == relay_of(id.id())) else {
            response.not_destroyed.append(id, SetError::not_found());
            continue;
        };
        if let std::collections::hash_map::Entry::Vacant(entry) = fetched.entry(relay.id) {
            entry.insert(queues(server, relay).await?);
        }
        let queues = &fetched[&relay.id];
        let Some(found) = queues.messages.iter().find(|f| f.id == id.id()) else {
            response.not_destroyed.append(id, SetError::not_found());
            continue;
        };
        let rid = found.relay_message_id.as_str();
        match found.direction {
            Direction::Inbound => {
                // Being taken just now: it is this server's mail already
                if found.object["state"].as_str() == Some("claimed") {
                    response.not_destroyed.append(
                        id,
                        SetError::forbidden()
                            .with_description("This server is taking it now; try again."),
                    );
                    continue;
                }
                let answer = queues
                    .linked
                    .sender
                    .call(method::INBOUND_SET, json!({"destroy": [rid]}))
                    .await
                    .map_err(|why| unavailable(relay, why))?;
                match destroyed(&answer, rid) {
                    Destroyed::Yes => response.destroyed.push(id),
                    Destroyed::NotFound => response.not_destroyed.append(id, SetError::not_found()),
                    Destroyed::Refused(error) => response.not_destroyed.append(id, error),
                }
            }
            Direction::Outbound => {
                // Cancelled here first, so the queue never hands it over
                // again once the relay drops it
                let handed = queues.handed.get(rid);
                if let Some(handed) = handed {
                    let cancelled: Vec<(String, RelayedStatus)> = handed
                        .recipients
                        .iter()
                        .map(|r| (r.clone(), RelayedStatus::Cancelled))
                        .collect();
                    if apply_relayed(
                        server,
                        handed.queue_id,
                        &handed.queue_name,
                        &relay.name,
                        &cancelled,
                    )
                    .await
                        == Applied::Locked
                    {
                        response.not_destroyed.append(
                            id,
                            SetError::forbidden().with_description(
                                "This server's queue is working on the message; try again.",
                            ),
                        );
                        continue;
                    }
                }
                let answer = queues
                    .linked
                    .sender
                    .call(method::OUTBOUND_SET, json!({"destroy": [rid]}))
                    .await
                    .map_err(|why| unavailable(relay, why))?;
                match destroyed(&answer, rid) {
                    // Cancelled here; the relay drops it after this attempt
                    Destroyed::Refused(error) => response.not_destroyed.append(id, error),
                    Destroyed::Yes | Destroyed::NotFound => {
                        if handed.is_some() {
                            outbound::forget_handed(data, relay.id, &[rid.to_string()]).await?;
                        }
                        response.destroyed.push(id);
                    }
                }
            }
        }
    }
    Ok(response)
}
