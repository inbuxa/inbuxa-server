/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    DavError, DavMethod,
    common::{
        ETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
    file::DavFileResource,
};
use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use dav_proto::{RequestHeaders, schema::property::Rfc1123DateTime};
use groupware::{cache::GroupwareCache, file::FileNode};
use http_proto::HttpResponse;
use hyper::StatusCode;
use store::{
    ValueKey,
    write::{AlignedBytes, Archive, now},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};

pub(crate) trait FileGetRequestHandler: Sync + Send {
    fn handle_file_get_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        is_head: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileGetRequestHandler for Server {
    async fn handle_file_get_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        is_head: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource_.account_id;
        let files = self
            .fetch_dav_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::FileNode,
            )
            .await
            .caused_by(trc::location!())?;
        let resource = files.map_resource(&resource_)?;

        // Fetch node
        let node_ = self
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::FileNode,
                resource.resource,
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let node = node_.unarchive::<FileNode>().caused_by(trc::location!())?;

        // Validate ACL
        if !access_token.is_member(account_id)
            && !node.acls.effective_acl(access_token).contains(Acl::Read)
        {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        let (hash, size, content_type) = if let Some(file) = node.file.as_ref() {
            (
                file.blob_hash.0.as_ref(),
                u32::from(file.size) as usize,
                file.media_type.as_ref().map(|s| s.as_str()),
            )
        } else {
            return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
        };

        // Validate headers
        let etag = node_.etag();
        self.validate_headers(
            access_token,
            headers,
            vec![ResourceState {
                account_id,
                collection: resource.collection,
                document_id: resource.resource.into(),
                etag: etag.clone().into(),
                path: resource_.resource.unwrap(),
                ..Default::default()
            }],
            Default::default(),
            DavMethod::GET,
        )
        .await?;

        let modified = i64::from(node.modified);
        let last_modified = Rfc1123DateTime::new(modified).to_string();
        let byte_range = if !is_head && size > 0 {
            headers
                .range
                .filter(|_| {
                    headers.eval_if_range(
                        &etag,
                        ((modified as u64) < now()).then_some(last_modified.as_str()),
                    )
                })
                .map(|range| range.resolve(size as u64))
        } else {
            None
        };
        let byte_range = match byte_range {
            Some(Some(range)) => Some(range.start as usize..range.end as usize),
            Some(None) => {
                return Ok(HttpResponse::new(StatusCode::RANGE_NOT_SATISFIABLE)
                    .with_header(hyper::header::CONTENT_SECURITY_POLICY, FILE_CSP)
                    .with_accept_ranges()
                    .with_etag(etag)
                    .with_content_range(format!("bytes */{size}")));
            }
            None => None,
        };

        let content_type = content_type.unwrap_or("application/octet-stream");
        let response = user_content_policy(
            HttpResponse::new(StatusCode::OK)
                .with_content_type(content_type)
                .with_etag(etag)
                .with_last_modified(last_modified)
                .with_accept_ranges(),
            content_type,
        );

        if is_head {
            return Ok(response.with_content_length(size));
        }

        let contents = self
            .blob_store()
            .get_blob(hash, byte_range.clone().unwrap_or(0..usize::MAX))
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

        Ok(match byte_range {
            Some(byte_range) if !contents.is_empty() => response
                .with_status_code(StatusCode::PARTIAL_CONTENT)
                .with_content_range(format!(
                    "bytes {}-{}/{}",
                    byte_range.start,
                    byte_range.start + contents.len() - 1,
                    size
                )),
            Some(_) => return Err(DavError::Code(StatusCode::NOT_FOUND)),
            None => response,
        }
        .with_binary_body(contents))
    }
}

/// inbuxa: a stored file is whatever its uploader sent, under the type they
/// claimed, and it is served on the same origin as the sign-in page, JMAP and
/// the console's API. Opened in a browser, an uploaded HTML or SVG page would
/// run as this server. So every file answer carries a sandbox policy, which
/// gives the document an opaque origin and no scripts, and only types that
/// can't hold active content are offered for display; everything else is a
/// download. WebDAV clients ignore both headers.
/// `frame-ancestors` is here so the default HTML headers don't add a second
/// policy of their own (security_headers.rs).
const FILE_CSP: &str = "default-src 'none'; frame-ancestors 'none'; sandbox";

fn user_content_policy(response: HttpResponse, content_type: &str) -> HttpResponse {
    let response = response
        .with_header(hyper::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .with_header(hyper::header::CONTENT_SECURITY_POLICY, FILE_CSP);
    if shown_inline(content_type) {
        response
    } else {
        response.with_content_disposition("attachment")
    }
}

/// Types a browser shows without running anything: raster images, audio,
/// video and plain text. SVG, HTML, XML, PDF and anything unknown download.
fn shown_inline(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    matches!(
        essence.as_str(),
        "image/png"
            | "image/jpeg"
            | "image/gif"
            | "image/webp"
            | "image/avif"
            | "image/bmp"
            | "text/plain"
    ) || ((essence.starts_with("audio/") || essence.starts_with("video/"))
        && !essence.contains("xml"))
}

#[cfg(test)]
mod tests {
    use super::shown_inline;

    #[test]
    fn active_types_download() {
        for ty in [
            "text/html",
            "TEXT/HTML; charset=utf-8",
            "application/xhtml+xml",
            "image/svg+xml",
            "text/xml",
            "application/xml",
            "application/pdf",
            "text/javascript",
            "application/octet-stream",
            "",
            "garbage",
            " text/html ",
        ] {
            assert!(!shown_inline(ty), "{ty:?} must download");
        }
    }

    #[test]
    fn passive_types_show() {
        for ty in [
            "image/png",
            "image/jpeg",
            "IMAGE/WEBP",
            "text/plain; charset=utf-8",
            "audio/mpeg",
            "video/mp4",
        ] {
            assert!(shown_inline(ty), "{ty:?} should show inline");
        }
    }
}
