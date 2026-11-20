/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// inbuxa: a stored file is served on the server's own origin, so an uploaded
// page must never run there. Every file answer carries a sandbox policy, and
// anything that could hold active content downloads instead of displaying.

use crate::utils::server::TestServer;
use hyper::StatusCode;

const BASE: &str = "/dav/file/john%40example.com";
const CSP: &str = "default-src 'none'; frame-ancestors 'none'; sandbox";

pub async fn test(test: &TestServer) {
    println!("Running WebDAV user content tests...");
    let client = test.account("john@example.com").webdav_client();

    for (name, content_type, body, download) in [
        ("page.html", "text/html", "<script>alert(1)</script>", true),
        (
            "page.xhtml",
            "application/xhtml+xml; charset=utf-8",
            "<html/>",
            true,
        ),
        (
            "pic.svg",
            "image/svg+xml",
            "<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
            true,
        ),
        ("doc.pdf", "application/pdf", "%PDF-1.4", true),
        ("none.bin", "", "x", true),
        ("note.txt", "text/plain", "hello", false),
        ("pic.png", "image/png", "png", false),
    ] {
        let path = format!("{BASE}/{name}");
        let headers: Vec<(&str, &str)> = if content_type.is_empty() {
            vec![]
        } else {
            vec![("content-type", content_type)]
        };
        client
            .request_with_headers("PUT", &path, headers, body)
            .await
            .with_status(StatusCode::CREATED);

        for method in ["GET", "HEAD"] {
            let response = client
                .request(method, &path, "")
                .await
                .with_status(StatusCode::OK)
                .with_header("content-security-policy", CSP)
                .with_header("x-content-type-options", "nosniff");
            assert_eq!(
                response
                    .headers
                    .get("content-disposition")
                    .map(String::as_str),
                download.then_some("attachment"),
                "{method} {name}"
            );
        }

        // A range of the file is the same file
        let response = client
            .request_with_headers("GET", &path, [("range", "bytes=0-0")], "")
            .await
            .with_status(StatusCode::PARTIAL_CONTENT)
            .with_header("content-security-policy", CSP);
        assert_eq!(
            response
                .headers
                .get("content-disposition")
                .map(String::as_str),
            download.then_some("attachment"),
            "range {name}"
        );

        client
            .request("DELETE", &path, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
}
