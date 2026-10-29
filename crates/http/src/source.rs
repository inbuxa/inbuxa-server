/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `/.well-known/source`: what the server runs and where its source is, in
//! the form https://coffeylabs.org/specs/well-known-source/ gives it.
//!
//! The server names its public repository and the commit it was built from.
//! A build that doesn't know its commit says nothing, and the address answers
//! 404, since a repository without a revision doesn't name the build.

use serde::Serialize;

#[derive(Serialize)]
struct Document<'a> {
    version: u32,
    software: [Software<'a>; 1],
}

#[derive(Serialize)]
struct Software<'a> {
    name: &'a str,
    version: &'a str,
    license: &'a str,
    repository: &'a str,
    revision: &'a str,
}

/// The document for this build, if it knows its commit.
pub fn document() -> Option<String> {
    document_for(types::branding::BUILD_REVISION)
}

fn document_for(revision: Option<&str>) -> Option<String> {
    let revision = revision.filter(|r| is_commit_id(r))?;
    serde_json::to_string(&Document {
        version: 1,
        software: [Software {
            name: types::brand_server!(),
            version: types::brand_version!(),
            license: "AGPL-3.0-only",
            repository: types::brand_repository!(),
            revision,
        }],
    })
    .ok()
}

/// A full commit id: 40 hex digits (SHA-1) or 64 (SHA-256).
fn is_commit_id(revision: &str) -> bool {
    matches!(revision.len(), 40 | 64) && revision.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::document_for;

    const COMMIT: &str = "f17b0943c2a1d5e8b7f6a9c0d1e2f3a4b5c6d7e8";

    #[test]
    fn names_the_repository_and_commit() {
        let doc: serde_json::Value =
            serde_json::from_str(&document_for(Some(COMMIT)).unwrap()).unwrap();
        assert_eq!(doc["version"], 1);
        let software = doc["software"].as_array().unwrap();
        assert_eq!(software.len(), 1);
        assert_eq!(software[0]["name"], types::brand_server!());
        assert_eq!(software[0]["version"], types::brand_version!());
        assert_eq!(software[0]["license"], "AGPL-3.0-only");
        assert_eq!(software[0]["repository"], types::brand_repository!());
        assert_eq!(software[0]["revision"], COMMIT);
    }

    #[test]
    fn says_nothing_without_a_full_commit() {
        let not_hex = COMMIT.replace('f', "g");
        for revision in [
            None,
            Some(""),
            Some("f17b094"),
            Some("v27.1"),
            Some(not_hex.as_str()),
        ] {
            assert_eq!(document_for(revision), None, "{revision:?}");
        }
    }
}
