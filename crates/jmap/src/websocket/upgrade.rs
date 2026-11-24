/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::stream::WebSocketHandler;
use common::{Server, auth::AccessToken};
use http_proto::*;
use hyper::StatusCode;
use hyper_util::rt::TokioIo;
use std::future::Future;
use tokio_tungstenite::WebSocketStream;
use trc::JmapEvent;
use tungstenite::{
    handshake::derive_accept_key,
    protocol::{Role, WebSocketConfig},
};

pub trait WebSocketUpgrade: Sync + Send {
    fn upgrade_websocket_connection(
        &self,
        req: HttpRequest,
        access_token: AccessToken,
        session: HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl WebSocketUpgrade for Server {
    async fn upgrade_websocket_connection(
        &self,
        req: HttpRequest,
        access_token: AccessToken,
        session: HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let headers = req.headers();
        let header_has_token = |name: hyper::header::HeaderName, token: &str| {
            headers
                .get(name)
                .and_then(|h| h.to_str().ok())
                .is_some_and(|value| {
                    value
                        .split(',')
                        .any(|part| part.trim().eq_ignore_ascii_case(token))
                })
        };
        if !header_has_token(hyper::header::CONNECTION, "Upgrade")
            || !header_has_token(hyper::header::UPGRADE, "websocket")
        {
            return Err(trc::ResourceEvent::BadParameters
                .into_err()
                .details("WebSocket upgrade failed")
                .ctx(
                    trc::Key::Reason,
                    "Missing or Invalid Connection or Upgrade headers.",
                ));
        }
        let derived_key = match (
            headers
                .get("Sec-WebSocket-Key")
                .and_then(|h| h.to_str().ok()),
            headers
                .get("Sec-WebSocket-Version")
                .and_then(|h| h.to_str().ok()),
        ) {
            (Some(key), Some("13")) => derive_accept_key(key.as_bytes()),
            _ => {
                return Err(trc::ResourceEvent::BadParameters
                    .into_err()
                    .details("WebSocket upgrade failed")
                    .ctx(
                        trc::Key::Reason,
                        "Missing or Invalid Sec-WebSocket-Key headers.",
                    ));
            }
        };

        // inbuxa: a message, or a frame, over the request size limit is
        // refused as its header arrives, not once it is all in memory
        let config = WebSocketConfig::default()
            .max_message_size(Some(self.core.jmap.request_max_size))
            .max_frame_size(Some(self.core.jmap.request_max_size));

        // Spawn WebSocket connection
        let jmap = self.clone();
        tokio::spawn(async move {
            // Upgrade connection
            let session_id = session.session_id;
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    Box::pin(
                        jmap.handle_websocket_stream(
                            WebSocketStream::from_raw_socket(
                                TokioIo::new(upgraded),
                                Role::Server,
                                Some(config),
                            )
                            .await,
                            access_token,
                            session,
                        ),
                    )
                    .await;
                }
                Err(err) => {
                    trc::event!(
                        Jmap(JmapEvent::WebsocketError),
                        Details = "Websocket upgrade failed",
                        SpanId = session_id,
                        Reason = err.to_string()
                    );
                }
            }
        });

        Ok(HttpResponse::new(StatusCode::SWITCHING_PROTOCOLS).with_websocket_upgrade(derived_key))
    }
}
