/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use serde::{Deserialize, Serialize};

/// Top-level configuration document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Configuration {
    /// Supported protocols and their server endpoints.
    pub protocols: Protocols,

    /// Authentication mechanisms the provider supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Authentication>,

    /// Informational metadata about the provider.
    pub info: Info,
}

/// The `protocols` object listing available protocol endpoints.
///
/// HTTP-based protocols (JMAP, CalDAV, CardDAV, WebDAV) use [`HttpServer`].
/// Text-based protocols (IMAP, POP3, SMTP, ManageSieve) use [`TextServer`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Protocols {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jmap: Option<HttpServer>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub imap: Option<TextServer>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pop3: Option<TextServer>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp: Option<TextServer>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub caldav: Option<HttpServer>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub carddav: Option<HttpServer>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub webdav: Option<HttpServer>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub managesieve: Option<TextServer>,
}

/// An HTTP-based protocol endpoint (JMAP, CalDAV, CardDAV, WebDAV).
///
/// The `url` MUST use the `https` scheme and the default port 443.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HttpServer {
    /// HTTPS URL of the protocol endpoint.
    pub url: String,
}

/// A text-based protocol endpoint (IMAP, POP3, SMTP, ManageSieve).
///
/// Connections use TLS on the protocol's default port
/// (993 IMAP, 995 POP3, 465 SMTP).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TextServer {
    /// Hostname of the server.
    pub host: String,
}

/// Authentication mechanisms supported by the provider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Authentication {
    /// OAuth Profile for Open Public Clients configuration.
    #[serde(rename = "oauth-public", skip_serializing_if = "Option::is_none")]
    pub oauth_public: Option<OAuthPublic>,

    /// Whether the provider supports username/password authentication.
    pub password: bool,
}

/// OAuth Profile for Open Public Clients parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OAuthPublic {
    /// The authorization server's issuer identifier (RFC 8414).
    /// Must be an `https` URL with no query or fragment components.
    pub issuer: String,
}

/// Informational metadata presented to users and developers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Info {
    /// Provider identity information (required).
    pub provider: Provider,

    /// Help links for users and developers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<Help>,
}

/// Provider identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Provider {
    /// Display name of the provider (≤ 60 characters, SHOULD ≤ 30).
    pub name: String,

    /// Short name (≤ 20 characters, SHOULD ≤ 12).
    #[serde(rename = "shortName", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,

    /// Logo image variants.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<Vec<Logo>>,
}

/// A single logo variant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Logo {
    /// URL where the logo can be retrieved.
    pub url: String,

    /// Media type of the logo image (e.g. `image/svg+xml`, `image/png`).
    #[serde(rename = "content-type")]
    pub content_type: String,

    /// Image width in pixels. Omitted for SVG.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,

    /// Image height in pixels. Omitted for SVG.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
}

/// Help links for users and developers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Help {
    /// URL with user-facing documentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation: Option<String>,

    /// URL with developer-facing documentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub developer: Option<String>,

    /// Contact URIs (e.g. `mailto:` URLs). NOT for end-user display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,
}

