/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

use common::Server;
use imap_proto::{
    ResponseCode, StatusResponse,
    protocol::capability::{AuthCapability, Capability},
};
use std::sync::LazyLock;

pub mod core;
pub mod op;

static SERVER_GREETING: &str = "Stalwart IMAP4rev2 at your service.";

const AUTH_CAPABILITIES: [AuthCapability; 3] = [
    AuthCapability::Disabled,
    AuthCapability::Plain,
    AuthCapability::PlainAndBearer,
];

static GREETINGS: LazyLock<[[Vec<u8>; 3]; 2]> = LazyLock::new(|| {
    [false, true].map(|offer_tls| AUTH_CAPABILITIES.map(|auth| build_greeting(offer_tls, auth)))
});

pub(crate) fn greeting(offer_tls: bool, auth: AuthCapability) -> &'static [u8] {
    &GREETINGS[usize::from(offer_tls)][auth as usize]
}

pub(crate) fn auth_capability(server: &Server, is_tls: bool) -> AuthCapability {
    if !is_tls && !server.core.imap.allow_plain_auth {
        AuthCapability::Disabled
    } else if server.accepts_bearer_tokens(is_tls) {
        AuthCapability::PlainAndBearer
    } else {
        AuthCapability::Plain
    }
}

fn build_greeting(offer_tls: bool, auth: AuthCapability) -> Vec<u8> {
    StatusResponse::ok(SERVER_GREETING)
        .with_code(ResponseCode::Capability {
            capabilities: Capability::all_capabilities(false, offer_tls, auth, 0, 0),
        })
        .into_bytes()
}

pub struct ImapError;
