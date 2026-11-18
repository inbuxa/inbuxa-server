/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: #401: links in QR codes in a message's images ("quishing").
//!
//! A phishing message can carry its link only as a QR code in an image, where
//! the URL checks, which read text, never see it. When `scanQrCodes` is on,
//! the images a message carries (image parts, and `data:` images in its HTML)
//! are read for QR codes, and the web links in them go through the same URL
//! checks as the message's other links, at location `qr_code`.
//!
//! Images come from the sender, so everything here is capped: which formats
//! are read (PNG, JPEG, GIF, WebP, sniffed from the bytes, not the declared
//! type), how many images, their size in bytes and pixels, how large they are
//! scanned, how many links are kept and how long a message may take. Decoding
//! runs on a blocking thread.

use crate::{SpamFilterContext, TextPart, modules::html::HtmlToken, modules::html::SRC};
use image::{ImageFormat, ImageReader, Limits};
use mail_parser::PartType;
use std::io::Cursor;
use std::time::{Duration, Instant};

/// The most images read in one message
pub(crate) const MAX_IMAGES: usize = 4;
/// Images larger than this, in bytes, are skipped
pub(crate) const MAX_IMAGE_BYTES: usize = 4 * 1024 * 1024;
/// Images with more pixels than this are skipped before they're decoded
pub(crate) const MAX_PIXELS: u64 = 16_000_000;
/// Images with a side shorter than this (spacers, tracking pixels, icons)
/// can't hold a readable QR code and are skipped
pub(crate) const MIN_SIDE: u32 = 64;
/// Larger images are scaled down to this longest side before they're scanned
pub(crate) const SCAN_SIDE: u32 = 1600;
/// No image is started once a message has taken this long
pub(crate) const TIME_BUDGET: Duration = Duration::from_millis(1000);
/// The most links kept from one message's QR codes
pub(crate) const MAX_URLS: usize = 10;
/// Longer QR texts aren't treated as links
const MAX_URL_LEN: usize = 2048;

/// The images in a message worth reading, copied so a blocking thread can
/// read them: image parts first, then `data:` images in HTML parts.
pub(crate) fn images(ctx: &SpamFilterContext<'_>) -> Vec<Vec<u8>> {
    let mut images = Vec::new();

    for part in &ctx.input.message.parts {
        if images.len() >= MAX_IMAGES {
            return images;
        }
        if let PartType::Binary(bytes) | PartType::InlineBinary(bytes) = &part.body
            && is_candidate(bytes)
        {
            images.push(bytes.to_vec());
        }
    }

    for part in &ctx.output.text_parts {
        if let TextPart::Html { html_tokens, .. } = part {
            for token in html_tokens {
                if let HtmlToken::StartTag { attributes, .. } = token {
                    for (attr, value) in attributes {
                        if images.len() >= MAX_IMAGES {
                            return images;
                        }
                        if *attr == SRC
                            && let Some(bytes) = value.as_deref().and_then(data_image)
                            && is_candidate(&bytes)
                        {
                            images.push(bytes);
                        }
                    }
                }
            }
        }
    }

    images
}

/// The bytes of a base64 `data:image/...` URL
fn data_image(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    let rest = value
        .get(..11)
        .filter(|scheme| scheme.eq_ignore_ascii_case("data:image/"))
        .map(|_| &value[11..])?;
    let (header, data) = rest.split_once(',')?;
    if !header.to_ascii_lowercase().ends_with(";base64")
        || data.len() > MAX_IMAGE_BYTES.div_ceil(3) * 4 + 4
    {
        return None;
    }
    mail_parser::decoders::base64::base64_decode(data.as_bytes())
}

fn format(bytes: &[u8]) -> Option<ImageFormat> {
    match infer::get(bytes)?.mime_type() {
        "image/png" => Some(ImageFormat::Png),
        "image/jpeg" => Some(ImageFormat::Jpeg),
        "image/gif" => Some(ImageFormat::Gif),
        "image/webp" => Some(ImageFormat::WebP),
        _ => None,
    }
}

fn is_candidate(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_IMAGE_BYTES && format(bytes).is_some()
}

/// The web links in the QR codes of these images, within the caps above
pub(crate) fn qr_urls(images: &[Vec<u8>]) -> Vec<String> {
    let started = Instant::now();
    let mut urls: Vec<String> = Vec::new();

    for image in images.iter().take(MAX_IMAGES) {
        if started.elapsed() >= TIME_BUDGET || urls.len() >= MAX_URLS {
            break;
        }
        for text in qr_texts(image) {
            if let Some(url) = as_url(&text)
                && !urls.contains(&url)
                && urls.len() < MAX_URLS
            {
                urls.push(url);
            }
        }
    }

    urls
}

/// The texts of the QR codes in one image; nothing for an image that isn't
/// one of the four formats, is outside the size caps or doesn't decode
pub(crate) fn qr_texts(bytes: &[u8]) -> Vec<String> {
    let Some(format) = format(bytes).filter(|_| bytes.len() <= MAX_IMAGE_BYTES) else {
        return vec![];
    };

    // The dimensions come from the header, before anything is decoded
    let Ok((width, height)) =
        ImageReader::with_format(Cursor::new(bytes), format).into_dimensions()
    else {
        return vec![];
    };
    if width.min(height) < MIN_SIDE || u64::from(width) * u64::from(height) > MAX_PIXELS {
        return vec![];
    }

    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(width);
    limits.max_image_height = Some(height);
    limits.max_alloc = Some(MAX_PIXELS * 4 + 16 * 1024 * 1024);
    reader.limits(limits);
    let Ok(image) = reader.decode() else {
        return vec![];
    };

    let image = if width.max(height) > SCAN_SIDE {
        image.thumbnail(SCAN_SIDE, SCAN_SIDE)
    } else {
        image
    };
    let luma = image.into_luma8();
    let (width, height) = luma.dimensions();
    let mut prepared =
        rqrr::PreparedImage::prepare_from_greyscale(width as usize, height as usize, |x, y| {
            luma.get_pixel(x as u32, y as u32).0[0]
        });

    prepared
        .detect_grids()
        .into_iter()
        .filter_map(|grid| grid.decode().ok().map(|(_, text)| text))
        .collect()
}

/// A QR code's text as a web link: only http and https, the way phones
/// open them
fn as_url(text: &str) -> Option<String> {
    let text = text.trim();
    if text.len() > MAX_URL_LEN || text.chars().any(|ch| ch.is_whitespace()) {
        return None;
    }
    let scheme = text.split_once("://")?.0;
    (scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
        .then(|| text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A QR code for the URL below, 287x287 PNG
    static QR_PNG: &[u8] = include_bytes!("../../../../tests/resources/spam-filter/qr/phish.png");
    // The same code on a 480x640 JPEG flyer, and a JPEG with no code
    static FLYER_JPG: &[u8] =
        include_bytes!("../../../../tests/resources/spam-filter/qr/flyer.jpg");
    static NO_QR_JPG: &[u8] =
        include_bytes!("../../../../tests/resources/spam-filter/qr/no-qr.jpg");
    const QR_URL: &str = "https://login-micros0ft-secure.example/verify?id=8f3a9c2b";

    #[test]
    fn reads_the_link_in_a_qr_code() {
        assert_eq!(qr_texts(QR_PNG), vec![QR_URL.to_string()]);
        assert_eq!(qr_urls(&[QR_PNG.to_vec()]), vec![QR_URL.to_string()]);
    }

    #[test]
    fn reads_a_photo_and_skips_one_without_a_code() {
        assert_eq!(qr_texts(FLYER_JPG), vec![QR_URL.to_string()]);
        assert!(qr_texts(NO_QR_JPG).is_empty());
    }

    #[test]
    fn reads_a_data_url() {
        let data = format!("data:image/png;base64,{}", base64_encode(QR_PNG));
        assert_eq!(data_image(&data).as_deref(), Some(QR_PNG));
        assert_eq!(data_image("data:text/html;base64,PGI+"), None);
        assert_eq!(data_image("https://example.com/a.png"), None);
    }

    #[test]
    fn skips_what_it_must_not_read() {
        // Not an image
        assert!(qr_texts(b"%PDF-1.7 not an image").is_empty());
        assert!(!is_candidate(b"plain text"));
        // Says it's a GIF, isn't one
        assert!(qr_texts(b"GIF89a").is_empty());
        // Too many bytes
        let mut big = QR_PNG.to_vec();
        big.resize(MAX_IMAGE_BYTES + 1, 0);
        assert!(!is_candidate(&big));
        assert!(qr_texts(&big).is_empty());
        // Too many pixels: a PNG header claiming 5000x5000, never decoded
        assert!(qr_texts(&png_header(5000, 5000)).is_empty());
        // Too small to hold a QR code
        assert!(qr_texts(&png_header(32, 32)).is_empty());
        // Truncated image
        assert!(qr_texts(&QR_PNG[..QR_PNG.len() / 2]).is_empty());
    }

    #[test]
    fn keeps_only_web_links() {
        assert_eq!(
            as_url(" HTTPS://a.example/x "),
            Some("HTTPS://a.example/x".into())
        );
        assert_eq!(as_url("http://a.example"), Some("http://a.example".into()));
        assert_eq!(as_url("WIFI:S:home;T:WPA;P:secret;;"), None);
        assert_eq!(as_url("tel:+15555550100"), None);
        assert_eq!(as_url("javascript://x"), None);
        assert_eq!(as_url("https://a.example/x y"), None);
        assert_eq!(
            as_url(&format!("https://a.example/{}", "x".repeat(MAX_URL_LEN))),
            None
        );
    }

    #[test]
    fn caps_the_images_read() {
        let many = vec![QR_PNG.to_vec(); MAX_IMAGES + 3];
        // Same link in every image: kept once
        assert_eq!(qr_urls(&many), vec![QR_URL.to_string()]);
    }

    fn png_header(width: u32, height: u32) -> Vec<u8> {
        let mut out = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
        out.extend_from_slice(&width.to_be_bytes());
        out.extend_from_slice(&height.to_be_bytes());
        out.extend_from_slice(&[8, 0, 0, 0, 0]);
        let crc = crc32(&out[12..]);
        out.extend_from_slice(&crc.to_be_bytes());
        out
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    fn base64_encode(bytes: &[u8]) -> String {
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(TABLE[(n >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }
}
