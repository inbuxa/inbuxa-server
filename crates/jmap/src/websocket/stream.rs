/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::api::{ToRequestError, notifications_into_push_objects, request::RequestHandler};
use common::{Server, auth::AccessToken, ipc::PushNotification};
use futures_util::{SinkExt, StreamExt};
use http_proto::HttpSessionData;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use jmap_proto::{
    error::request::RequestError,
    request::websocket::{
        WebSocketMessage, WebSocketPushObject, WebSocketRequestError, WebSocketResponse,
    },
};
use std::future::Future;
use std::net::IpAddr;
use std::time::Instant;
use store::write::now;
use tokio_tungstenite::WebSocketStream;
use trc::JmapEvent;
use tungstenite::Message;
use types::type_state::{DataType, StateChange};
use utils::map::bitmap::Bitmap;

pub trait WebSocketHandler: Sync + Send {
    fn handle_websocket_stream(
        &self,
        stream: WebSocketStream<TokioIo<Upgraded>>,
        access_token: AccessToken,
        session: HttpSessionData,
    ) -> impl Future<Output = ()> + Send;
}

impl WebSocketHandler for Server {
    async fn handle_websocket_stream(
        &self,
        mut stream: WebSocketStream<TokioIo<Upgraded>>,
        access_token: AccessToken,
        session: HttpSessionData,
    ) {
        trc::event!(
            Jmap(JmapEvent::WebsocketStart),
            SpanId = session.session_id,
            AccountId = access_token.account_id(),
        );

        // Set timeouts
        let throttle = self.core.jmap.web_socket_throttle;
        let timeout = self.core.jmap.web_socket_timeout;
        let heartbeat = self.core.jmap.web_socket_heartbeat;
        let mut last_request = Instant::now();
        let mut last_changes_sent = Instant::now() - throttle;
        let mut last_heartbeat = Instant::now() - heartbeat;
        let mut next_event = heartbeat;

        // Register with push manager
        let mut push_rx = match self
            .subscribe_push_manager(&access_token, Bitmap::all())
            .await
        {
            Ok(push_rx) => push_rx,
            Err(err) => {
                trc::error!(
                    err.details("Failed to subscribe to push manager")
                        .span_id(session.session_id)
                );

                let _ = stream
                    .send(Message::Text(
                        WebSocketRequestError::from(RequestError::internal_server_error())
                            .to_json()
                            .into(),
                    ))
                    .await;
                return;
            }
        };

        let mut notifications = Vec::new();
        let mut change_types: Bitmap<DataType> = Bitmap::new();

        loop {
            tokio::select! {
                event = tokio::time::timeout(next_event, stream.next()) => {
                    match event {
                        Ok(Some(Ok(event))) => {
                            match event {
                                Message::Text(text) => {
                                    let response = match WebSocketMessage::parse(
                                        text.as_bytes(),
                                        self.core.jmap.request_max_calls,
                                        self.core.jmap.request_max_size,
                                    ) {
                                        Ok(WebSocketMessage::Request(request)) => {
                                            // inbuxa: each request is served as the
                                            // session stands now, and counts toward
                                            // the account's request limits
                                            let access_token = match current_websocket_token(
                                                self,
                                                &access_token,
                                                session.remote_ip,
                                            )
                                            .await
                                            {
                                                Ok(access_token) => access_token,
                                                Err(err) => {
                                                    end_websocket(&mut stream, err, session.session_id).await;
                                                    break;
                                                }
                                            };
                                            match self
                                                .is_http_authenticated_request_allowed(
                                                    &access_token,
                                                    session.remote_ip,
                                                )
                                                .await
                                            {
                                                Ok(_in_flight) => {
                                                    let response = self
                                                        .handle_jmap_request(
                                                            request.request,
                                                            &access_token,
                                                            &session,
                                                        )
                                                        .await;
                                                    WebSocketResponse::from_response(response, request.id)
                                                    .to_json()
                                                }
                                                Err(err) => {
                                                    WebSocketRequestError::from(err.to_request_error()).to_json()
                                                }
                                            }
                                        }
                                        Ok(WebSocketMessage::PushEnable(push_enable)) => {
                                            change_types = if !push_enable.data_types.is_empty() {
                                                push_enable.data_types.into()
                                            } else {
                                                Bitmap::all()
                                            };
                                            continue;
                                        }
                                        Ok(WebSocketMessage::PushDisable) => {
                                            change_types = Bitmap::new();
                                            continue;
                                        }
                                        Err(err) => {
                                            let response = WebSocketRequestError::from(err.to_request_error()).to_json();
                                            trc::error!(err.details("Failed to parse WebSocket message").span_id(session.session_id));
                                            response
                                        },
                                    };
                                    if let Err(err) = stream.send(Message::Text(response.into())).await {
                                        trc::event!(Jmap(JmapEvent::WebsocketError),
                                                    Details = "Failed to send text message",
                                                    SpanId = session.session_id,
                                                    Reason = err.to_string()
                                        );
                                    }
                                }
                                Message::Ping(bytes) => {
                                    if let Err(err) = stream.send(Message::Pong(bytes)).await {
                                        trc::event!(Jmap(JmapEvent::WebsocketError),
                                                    Details = "Failed to send pong message",
                                                    SpanId = session.session_id,
                                                    Reason = err.to_string()
                                        );
                                    }
                                }
                                Message::Close(frame) => {
                                    let _ = stream.close(frame).await;
                                    break;
                                }
                                _ => (),
                            }

                            last_request = Instant::now();
                            last_heartbeat = Instant::now();
                        }
                        Ok(Some(Err(err))) => {
                            trc::event!(Jmap(JmapEvent::WebsocketError),
                                                    Details = "Websocket error",
                                                    SpanId = session.session_id,
                                                    Reason = err.to_string()
                                        );
                            break;
                        }
                        Ok(None) => break,
                        Err(_) => {
                            // Verify timeout
                            if last_request.elapsed() > timeout {
                                trc::event!(
                                    Jmap(JmapEvent::WebsocketStop),
                                    SpanId = session.session_id,
                                    Reason = "Idle client"
                                );

                                break;
                            }
                        }
                    }
                }
                push_notification = push_rx.recv() => {
                    if let Some(push_notification) = push_notification {
                        match push_notification {
                            PushNotification::StateChange(state_change) => {
                                let mut types = state_change.types;
                                types.intersection(&change_types);

                                if !types.is_empty() {
                                    notifications.push(PushNotification::StateChange(
                                        StateChange {
                                            account_id: state_change.account_id,
                                            types,
                                            change_id: state_change.change_id,
                                        }
                                    ));
                                }
                            },
                            PushNotification::EmailPush(email_push) => {
                                let state_change = email_push.to_state_change();
                                let mut types = state_change.types;
                                types.intersection(&change_types);

                                if !types.is_empty() {
                                    notifications.push(PushNotification::StateChange(
                                        StateChange {
                                            account_id: state_change.account_id,
                                            types,
                                            change_id: state_change.change_id,
                                        }
                                    ));
                                }
                            },
                            PushNotification::CalendarAlert(calendar_alert) => {
                                if change_types.contains(DataType::CalendarAlert) {
                                    notifications.push(PushNotification::CalendarAlert(
                                        calendar_alert
                                    ));
                                }
                            },
                        }

                    } else {
                        trc::event!(
                            Jmap(JmapEvent::WebsocketStop),
                            SpanId = session.session_id,
                            Reason = "State manager channel closed"
                        );

                        break;
                    }
                }
            }

            if !notifications.is_empty() {
                // Send any queued changes
                let elapsed = last_changes_sent.elapsed();
                if elapsed >= throttle {
                    // inbuxa: only while the session is still valid
                    if let Err(err) =
                        current_websocket_token(self, &access_token, session.remote_ip).await
                    {
                        end_websocket(&mut stream, err, session.session_id).await;
                        break;
                    }
                    for push in notifications_into_push_objects(std::mem::take(&mut notifications))
                    {
                        let payload = WebSocketPushObject {
                            push,
                            push_state: None,
                        };
                        if let Err(err) = stream.send(Message::Text(payload.to_json().into())).await
                        {
                            trc::event!(
                                Jmap(JmapEvent::WebsocketError),
                                Details = "Failed to send state change message.",
                                SpanId = session.session_id,
                                Reason = err.to_string()
                            );
                        }
                    }
                    last_changes_sent = Instant::now();
                    last_heartbeat = Instant::now();
                    next_event = heartbeat;
                } else {
                    next_event = throttle - elapsed;
                }
            } else if last_heartbeat.elapsed() > heartbeat {
                if let Err(err) = stream.send(Message::Ping(Vec::<u8>::new().into())).await {
                    trc::event!(
                        Jmap(JmapEvent::WebsocketError),
                        Details = "Failed to send ping message.",
                        SpanId = session.session_id,
                        Reason = err.to_string()
                    );
                    break;
                }
                last_heartbeat = Instant::now();
                next_event = heartbeat;
            }
        }
    }
}

/// inbuxa: the WebSocket's access token as it stands now. The socket
/// outlives the request that opened it, so it ends when the bearer token it
/// signed in with expires, the account is locked or removed, the password
/// changes, or the app password or API key it used goes; and each request
/// sees the account's current permissions and shares.
async fn current_websocket_token(
    server: &Server,
    signed_in: &AccessToken,
    remote_ip: IpAddr,
) -> trc::Result<AccessToken> {
    if signed_in
        .expires_at()
        .is_some_and(|expires_at| expires_at <= now())
    {
        return Err(trc::AuthEvent::TokenExpired.into_err());
    }
    let inner = server.access_token(signed_in.account_id()).await?;
    if inner.is_locked() {
        return Err(trc::AuthEvent::Failed
            .into_err()
            .details("Account is locked"));
    }
    // A session that signed in with an app password or API key ends when
    // that credential goes, which renewing it below checks
    if signed_in.credential_id().is_none()
        && inner.credential_version() != signed_in.credential_version()
    {
        return Err(trc::AuthEvent::TokenExpired
            .into_err()
            .details("Credentials changed"));
    }
    AccessToken::renew(inner, signed_in.credential_id(), remote_ip).map(|access_token| {
        access_token
            .with_origin_arc(signed_in.origin_arc())
            .with_expires_at(signed_in.expires_at())
    })
}

/// inbuxa: tells the client its session is over and closes the socket.
async fn end_websocket(
    stream: &mut WebSocketStream<TokioIo<Upgraded>>,
    err: trc::Error,
    session_id: u64,
) {
    trc::event!(
        Jmap(JmapEvent::WebsocketStop),
        SpanId = session_id,
        Reason = "Session no longer authorized",
        CausedBy = err,
    );
    let _ = stream
        .send(Message::Text(
            WebSocketRequestError::from(RequestError::unauthorized())
                .to_json()
                .into(),
        ))
        .await;
    let _ = stream.close(None).await;
}
