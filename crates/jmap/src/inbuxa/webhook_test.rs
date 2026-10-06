/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `POST /api/webhook/test`: send one sample event to a saved webhook
//! (settings-reorg, Webhooks "Send test").
//!
//! ```json
//! {"webhookId": "b"}
//! ```
//!
//! The answer is `{"sent": true, "status": 200, "ms": 84}` when the receiver
//! answered 2xx, `{"sent": false, "status": 403, …}` when it answered
//! otherwise, and `{"sent": false, "error": "…"}` when nothing came back. The
//! webhook is used as saved, even when it's off, so it can be tried before
//! it's switched on. The request goes where the saved webhook already sends,
//! so this gives nobody a reach they didn't have.
//!
//! For server-level administrators who may change webhooks.

use common::{Server, auth::AccessToken};
use registry::schema::{enums::Permission, structs::WebHook};
use serde_json::{Value, json};
use std::{str::FromStr, time::Instant};
use types::id::Id;

pub fn assert_allowed(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        return Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("Webhook tests are for server-level administrators."));
    }
    access_token.enforce_permission(Permission::SysWebHookUpdate)
}

pub async fn test(server: &Server, body: &Value) -> trc::Result<Value> {
    let webhook_id = body
        .get("webhookId")
        .and_then(Value::as_str)
        .and_then(|id| Id::from_str(id).ok())
        .ok_or_else(|| {
            trc::ResourceEvent::BadParameters
                .into_err()
                .details("Expected {\"webhookId\": …}")
        })?;
    let Some(hook) = server.registry().object::<WebHook>(webhook_id).await? else {
        return Ok(json!({ "sent": false, "error": "There's no such webhook. Save it first." }));
    };

    let started = Instant::now();
    Ok(match common::telemetry::webhooks::send_test(&hook).await {
        Ok(status) => json!({
            "sent": (200..300).contains(&status),
            "status": status,
            "ms": started.elapsed().as_millis() as u64,
        }),
        Err(error) => json!({ "sent": false, "error": error }),
    })
}
