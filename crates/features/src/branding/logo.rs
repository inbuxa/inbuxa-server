/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Logo values: what may be written (BT-3), how stored ones are read
//! (BT-4), and which logo applies (BT-1, BT-9). The server never fetches a
//! logo URL (BT-7): a URL is only ever handed on.

use base64::{Engine, engine::general_purpose::STANDARD};

/// The largest image a data URL may hold (BT-3).
pub const MAX_IMAGE_SIZE: usize = 256 * 1024;

/// The image types a logo may be (BT-3).
pub const TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/svg+xml",
];

/// A logo, read from a stored value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Logo {
    /// A URL, handed to browsers and mail clients as it is.
    Url(String),
    /// An image, from a data URL or bare base64.
    Image {
        content_type: &'static str,
        bytes: Vec<u8>,
    },
}

impl Logo {
    /// Whether mail can carry it inline: PNG, JPEG or GIF only (BT-9).
    pub fn is_embeddable(&self) -> bool {
        matches!(
            self,
            Logo::Image {
                content_type: "image/png" | "image/jpeg" | "image/gif",
                ..
            }
        )
    }
}

/// The type an image's bytes show, if one of `TYPES`.
pub fn sniff(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if is_svg(bytes) {
        Some("image/svg+xml")
    } else {
        None
    }
}

/// SVG is text: an `<svg` element near the start, after any BOM, XML
/// declaration, comments or doctype.
fn is_svg(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(4096)];
    let Ok(text) = std::str::from_utf8(head).or_else(|err| {
        // The cut may split a character
        std::str::from_utf8(&head[..err.valid_up_to()])
    }) else {
        return false;
    };
    let text = text.trim_start_matches('\u{feff}').trim_start();
    text.starts_with('<') && text.to_ascii_lowercase().contains("<svg")
}

fn has_scheme(value: &str, scheme: &str) -> bool {
    value
        .get(..scheme.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(scheme))
}

/// A URL a browser may load: the scheme, a host, and no spaces or controls.
fn is_url(value: &str, scheme: &str) -> bool {
    has_scheme(value, scheme)
        && value[scheme.len()..]
            .strip_prefix("//")
            .and_then(|rest| rest.chars().next())
            .is_some_and(|c| !matches!(c, '/' | '?' | '#'))
        && !value.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// A `data:` URL's type and decoded bytes, when it's base64.
fn data_url(value: &str) -> Result<(String, Vec<u8>), &'static str> {
    let rest = value.get(5..).ok_or("not a data URL")?;
    let (header, data) = rest.split_once(',').ok_or("a data URL needs a comma")?;
    let mut params = header.split(';');
    let media_type = params.next().unwrap_or_default().trim().to_ascii_lowercase();
    if !params.any(|p| p.trim().eq_ignore_ascii_case("base64")) {
        return Err("a data URL logo must be base64");
    }
    let data = data
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect::<String>();
    let bytes = STANDARD
        .decode(data.as_bytes())
        .map_err(|_| "the data URL isn't valid base64")?;
    Ok((media_type, bytes))
}

/// Checks a logo being written (BT-3): an `https:` URL, or a base64 data URL
/// of one of `TYPES`, at most `MAX_IMAGE_SIZE`, whose bytes are that type.
pub fn check(value: &str) -> Result<(), String> {
    if has_scheme(value, "data:") {
        let (media_type, bytes) = data_url(value).map_err(str::to_string)?;
        let Some(declared) = TYPES.iter().find(|t| **t == media_type) else {
            return Err(format!(
                "A logo must be PNG, JPEG, GIF, WebP or SVG, not {media_type:?}."
            ));
        };
        if bytes.len() > MAX_IMAGE_SIZE {
            return Err(format!(
                "The logo is {} KiB; the limit is 256 KiB.",
                bytes.len().div_ceil(1024)
            ));
        }
        match sniff(&bytes) {
            Some(found) if found == *declared => Ok(()),
            _ => Err(format!("The logo's bytes aren't {declared}.")),
        }
    } else if is_url(value, "https:") {
        Ok(())
    } else {
        Err("A logo must be an https: URL or a base64 data: URL of an image.".to_string())
    }
}

/// Reads a stored logo (BT-4): anything `check` accepts, an `http:` URL, a
/// base64 data URL of an image, or bare base64 whose bytes are an image.
/// `None` for a value that is none of these, or empty.
pub fn read(value: &str) -> Option<Logo> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else if has_scheme(value, "data:") {
        let (media_type, bytes) = data_url(value).ok()?;
        let found = sniff(&bytes)?;
        // The bytes decide, so a mislabelled image is still served as what it is
        (media_type.starts_with("image/")).then_some(Logo::Image {
            content_type: found,
            bytes,
        })
    } else if is_url(value, "https:") || is_url(value, "http:") {
        Some(Logo::Url(value.to_string()))
    } else {
        let data = value
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>();
        let bytes = STANDARD.decode(data.as_bytes()).ok()?;
        sniff(&bytes).map(|content_type| Logo::Image {
            content_type,
            bytes,
        })
    }
}

/// Where a logo value came from, for the warning about an unusable one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Domain(u32),
    Tenant(u32),
    Server,
}

/// The logos that apply, most specific first (BT-1): the domain's, its
/// tenant's, then the server-wide one. Unusable values are skipped with a
/// `registry.build-warning` (BT-4). The built-in logo is the caller's last
/// resort.
pub fn chain<'x>(
    candidates: impl IntoIterator<Item = (Source, Option<&'x str>)>,
) -> Vec<Logo> {
    let mut logos = Vec::new();
    for (source, value) in candidates {
        let Some(value) = value.filter(|v| !v.trim().is_empty()) else {
            continue;
        };
        match read(value) {
            Some(logo) => logos.push(logo),
            None => trc::event!(
                Registry(trc::RegistryEvent::BuildWarning),
                Details = format!("Unusable logo on {source:?}, skipped (BT-4)")
            ),
        }
    }
    logos
}

/// The names to try for a domain name D (BT-1): D, then D without its
/// leftmost label while at least two labels remain. Lowercase.
pub fn lookup_names(name: &str) -> Vec<String> {
    let mut name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    // A Host header may carry a port
    if let Some((host, port)) = name.rsplit_once(':')
        && !host.contains(':')
        && port.chars().all(|c| c.is_ascii_digit())
    {
        name = host.to_string();
    }
    let mut names = Vec::new();
    let mut rest = name.as_str();
    while !rest.is_empty() {
        names.push(rest.to_string());
        match rest.split_once('.') {
            Some((_, parent)) if parent.contains('.') => rest = parent,
            _ => break,
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";
    const JPEG: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10];

    fn data(media_type: &str, bytes: &[u8]) -> String {
        format!("data:{media_type};base64,{}", STANDARD.encode(bytes))
    }

    #[test]
    fn writes() {
        assert!(check("https://example.org/logo.png").is_ok());
        assert!(check(&data("image/png", PNG)).is_ok());
        assert!(check(&data("image/svg+xml", b"<?xml version=\"1.0\"?><svg/>")).is_ok());
        for bad in [
            "javascript:alert(1)".to_string(),
            "http://example.org/logo.png".to_string(),
            "https://".to_string(),
            "https://exa mple.org/".to_string(),
            "data:text/html,<b>x</b>".to_string(),
            data("text/html", b"<b>x</b>"),
            data("image/png", JPEG),
            data("image/png", &[PNG, &vec![0u8; 300 * 1024]].concat()),
            "admin".to_string(),
        ] {
            assert!(check(&bad).is_err(), "{bad:.60}");
        }
    }

    #[test]
    fn reads() {
        assert_eq!(
            read("http://example.org/l.png"),
            Some(Logo::Url("http://example.org/l.png".into()))
        );
        assert_eq!(
            read(&STANDARD.encode(PNG)),
            Some(Logo::Image {
                content_type: "image/png",
                bytes: PNG.to_vec()
            })
        );
        // Mislabelled: served as what it is
        assert_eq!(
            read(&data("image/png", JPEG)),
            Some(Logo::Image {
                content_type: "image/jpeg",
                bytes: JPEG.to_vec()
            })
        );
        assert_eq!(read("admin"), None);
        assert_eq!(read(""), None);
        assert_eq!(read(&data("text/html", b"<b>x</b>")), None);
    }

    #[test]
    fn chain_order_and_embedding() {
        let png = data("image/png", PNG);
        let svg = data("image/svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg'/>");
        let logos = chain([
            (Source::Domain(1), Some("admin")),
            (Source::Tenant(2), Some(svg.as_str())),
            (Source::Server, Some(png.as_str())),
        ]);
        assert_eq!(logos.len(), 2);
        assert!(!logos[0].is_embeddable());
        assert!(logos[1].is_embeddable());
    }

    #[test]
    fn names() {
        assert_eq!(
            lookup_names("Mail.Example.COM:8443"),
            vec!["mail.example.com", "example.com"]
        );
        assert_eq!(lookup_names("example.com"), vec!["example.com"]);
        assert_eq!(lookup_names("localhost"), vec!["localhost"]);
    }
}
