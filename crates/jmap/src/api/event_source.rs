/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::api::IntoPushObject;
use common::{
    LONG_1D_SLUMBER, Server,
    auth::{AccessToken, SESSION_RECHECK_INTERVAL},
    ipc::PushNotification,
};
use http_body_util::{StreamBody, combinators::BoxBody};
use http_proto::*;
use hyper::{
    StatusCode,
    body::{Bytes, Frame},
};
use jmap_proto::{response::status::PushObject, types::state::State};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use std::{future::Future, str::FromStr};
use types::{id::Id, type_state::DataType};
use utils::map::{bitmap::Bitmap, vec_map::VecMap};

struct Ping {
    interval: Duration,
    last_ping: Instant,
    payload: Bytes,
}

pub trait EventSourceHandler: Sync + Send {
    fn handle_event_source(
        &self,
        req: HttpRequest,
        access_token: AccessToken,
        remote_ip: IpAddr,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl EventSourceHandler for Server {
    async fn handle_event_source(
        &self,
        req: HttpRequest,
        access_token: AccessToken,
        remote_ip: IpAddr,
    ) -> trc::Result<HttpResponse> {
        // Parse query
        let mut ping = 0;
        let mut types = Bitmap::default();
        let mut close_after_state = false;

        for (key, value) in
            http_proto::form_urlencoded::parse(req.uri().query().unwrap_or_default().as_bytes())
        {
            hashify::fnc_map!(key.as_bytes(),
                "types" => {
                    for type_state in value.split(',') {
                        if type_state == "*" {
                            types = Bitmap::all();
                            break;
                        } else if let Ok(type_state) = DataType::from_str(type_state) {
                            types.insert(type_state);
                        } else {
                            return Err(trc::ResourceEvent::BadParameters.into_err());
                        }
                    }
                },
                "closeafter" => match value.as_ref() {
                    "state" => {
                        close_after_state = true;
                    }
                    "no" => {}
                    _ => return Err(trc::ResourceEvent::BadParameters.into_err()),
                },
                "ping" => match value.parse::<u32>() {
                    Ok(value) => {
                        ping = value;
                    }
                    Err(_) => return Err(trc::ResourceEvent::BadParameters.into_err()),
                },
                _ => {}
            );
        }

        let mut ping = if ping > 0 {
            #[cfg(not(feature = "test_mode"))]
            let interval = std::cmp::max(ping, 30);
            #[cfg(feature = "test_mode")]
            let interval = ping;
            let interval_duration = Duration::from_secs(interval as u64);

            Ping {
                interval: interval_duration,
                last_ping: Instant::now() - interval_duration,
                payload: Bytes::from(format!(
                    "event: ping\ndata: {{\"interval\": {}}}\n\n",
                    interval
                )),
            }
            .into()
        } else {
            None
        };

        // Register with push manager
        let mut push_rx = self.subscribe_push_manager(&access_token, types).await?;
        let mut changed: VecMap<Id, VecMap<DataType, State>> = VecMap::new();
        let throttle = self.core.jmap.event_source_throttle;
        let server = self.clone();

        Ok(HttpResponse::new(StatusCode::OK)
            .with_content_type("text/event-stream")
            .with_cache_control("no-store")
            .with_stream_body(BoxBody::new(StreamBody::new(async_stream::stream! {
                let mut last_message = Instant::now() - throttle;
                let mut timeout = ping
                    .as_ref()
                    .map(|p| p.interval)
                    .unwrap_or(LONG_1D_SLUMBER)
                    .min(SESSION_RECHECK_INTERVAL);

                loop {
                    let event = tokio::time::timeout(timeout, push_rx.recv()).await;
                    // inbuxa: the stream ends once the sign-in it was opened
                    // with is no longer valid, or the account has lost
                    // permissions or shares it holds
                    // inbuxa: the check runs as a task of its own, so this
                    // stream stays Sync: with the SQL and Redis store backends
                    // its futures aren't, and the response body has to be. A
                    // check that can't finish ends the stream.
                    let check = {
                        let server = server.clone();
                        let access_token = access_token.clone();
                        tokio::spawn(async move {
                            server.assert_session_current(&access_token, remote_ip).await
                        })
                    };
                    match check.await {
                        Ok(Ok(())) => (),
                        Ok(Err(err)) => {
                            trc::error!(err.details("EventSource stream ended"));
                            break;
                        }
                        Err(_) => break,
                    }

                    match event {
                        Ok(Some(notification)) => {
                            match notification {
                                PushNotification::StateChange(state_change) => {
                                    for type_state in state_change.types {
                                        changed
                                            .get_mut_or_insert(state_change.account_id.into())
                                            .set(type_state, State::Exact(state_change.change_id));
                                    }
                                }
                                PushNotification::CalendarAlert(calendar_alert) => {
                                    yield Ok(Frame::data(Bytes::from(format!(
                                        "event: calendarAlert\ndata: {}\n\n",
                                        serde_json::to_string(&calendar_alert.into_push_object()).unwrap()
                                    ))));
                                }
                                PushNotification::EmailPush(email_push) => {
                                    let state_change = email_push.to_state_change();
                                    for type_state in state_change.types {
                                        changed
                                            .get_mut_or_insert(state_change.account_id.into())
                                            .set(type_state, State::Exact(state_change.change_id));
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            break;
                        }
                        Err(_) => (),
                    }

                    timeout = if !changed.is_empty() {
                        let elapsed = last_message.elapsed();
                        if elapsed >= throttle {
                            last_message = Instant::now();
                            let response =
                                PushObject::StateChange { changed: std::mem::take(&mut changed) };

                            yield Ok(Frame::data(Bytes::from(format!(
                                "event: state\ndata: {}\n\n",
                                serde_json::to_string(&response).unwrap()
                            ))));

                            if close_after_state {
                                break;
                            }

                            ping.as_ref().map(|p| p.interval).unwrap_or(LONG_1D_SLUMBER)
                        } else {
                            throttle - elapsed
                        }
                    } else if let Some(ping) = &mut ping {
                        let elapsed = ping.last_ping.elapsed();
                        if elapsed >= ping.interval {
                            ping.last_ping = Instant::now();
                            yield Ok(Frame::data(ping.payload.clone()));
                            ping.interval
                        } else {
                            ping.interval - elapsed
                        }
                    } else {
                        LONG_1D_SLUMBER
                    }
                    .min(SESSION_RECHECK_INTERVAL);
                }
            }))))
    }
}
