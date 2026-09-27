/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Who a registry write is for, carried with the task that makes it.
//!
//! A JMAP request records its own changes, with the actor and what was
//! asked (AU-1.1), so the registry's write hook stays quiet inside one. A
//! write outside any request is the server acting on its own (AU-1.10) and
//! is recorded by the hook, under the subsystem named here or as
//! `system:server` when none is.

use std::future::Future;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// A request that records its own changes.
    Request,
    /// The server acting on its own, in the named subsystem.
    System(&'static str),
    /// Writes counted, not recorded one by one: a bulk update records one
    /// summary itself (spam rules from an update, for one).
    Quiet,
}

tokio::task_local! {
    static SCOPE: Scope;
}

/// Runs `f` as a request that records its own changes.
pub async fn request<F: Future>(f: F) -> F::Output {
    SCOPE.scope(Scope::Request, f).await
}

/// Runs `f` as the server's own `subsystem`.
pub async fn system<F: Future>(subsystem: &'static str, f: F) -> F::Output {
    SCOPE.scope(Scope::System(subsystem), f).await
}

/// Runs `f` without recording its registry writes one by one.
pub async fn quiet<F: Future>(f: F) -> F::Output {
    SCOPE.scope(Scope::Quiet, f).await
}

/// The scope the current task runs in, if any.
pub fn current() -> Option<Scope> {
    SCOPE.try_with(|scope| *scope).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn nested_scopes() {
        assert_eq!(current(), None);
        system("acme", async {
            assert_eq!(current(), Some(Scope::System("acme")));
            request(async {
                assert_eq!(current(), Some(Scope::Request));
            })
            .await;
            assert_eq!(current(), Some(Scope::System("acme")));
        })
        .await;
        assert_eq!(current(), None);
    }
}
