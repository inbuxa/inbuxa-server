/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{LdapConnection, LdapConnectionManager, LdapConnector};
use deadpool::managed;
use ldap3::{Ldap, LdapConnAsync, LdapError, exop::WhoAmI};
use std::{io, time::Duration};
use tokio::time::timeout;
use trc::{EventType, Key, StoreEvent};

const RECYCLE_PROBE_AFTER_IDLE: Duration = Duration::from_secs(5);

impl managed::Manager for LdapConnectionManager {
    type Type = LdapConnection;
    type Error = LdapError;

    async fn create(&self) -> Result<LdapConnection, LdapError> {
        self.probe_primary();

        let start = self.servers.start();
        let mut last_error = None;

        for (server, url) in self.servers.connect_order(start) {
            match self
                .connector
                .connect(url, self.servers.has_failover())
                .await
            {
                Ok(ldap) => {
                    self.servers.connected(start, server);
                    return Ok(LdapConnection { ldap, server });
                }
                Err(err) => {
                    if self.servers.has_failover() {
                        trc::event!(
                            Store(trc::StoreEvent::LdapWarning),
                            Reason = "Failed to connect to LDAP server",
                            Url = url.to_string(),
                            Details = err.to_string()
                        );
                    }
                    last_error = Some(err);
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| LdapError::from(io::Error::other("no LDAP server is configured"))))
    }

    async fn recycle(
        &self,
        conn: &mut LdapConnection,
        metrics: &managed::Metrics,
    ) -> managed::RecycleResult<LdapError> {
        self.probe_primary();

        if conn.ldap.is_closed() {
            Err(managed::RecycleError::message("LDAP connection closed"))
        } else if conn.server != self.servers.active() {
            Err(managed::RecycleError::message("LDAP server switched"))
        } else if metrics.last_used() < RECYCLE_PROBE_AFTER_IDLE {
            Ok(())
        } else {
            conn.ldap
                .extended(WhoAmI)
                .await
                .map(|_| ())
                .map_err(managed::RecycleError::Backend)
        }
    }
}

impl LdapConnectionManager {
    fn probe_primary(&self) {
        if !self.servers.claim_primary_probe() {
            return;
        }

        let servers = self.servers.clone();
        let connector = self.connector.clone();
        tokio::spawn(async move {
            match connector.connect(servers.primary(), true).await {
                Ok(mut ldap) => {
                    let _ = ldap.unbind().await;
                    servers.primary_recovered();
                }
                Err(err) => {
                    trc::event!(
                        Store(trc::StoreEvent::LdapWarning),
                        Reason = "Primary LDAP server is still unreachable",
                        Url = servers.primary().to_string(),
                        Details = err.to_string()
                    );
                }
            }
        });
    }
}

impl LdapConnector {
    async fn connect(&self, url: &str, verify: bool) -> Result<Ldap, LdapError> {
        timeout(self.timeout, async {
            let (conn, mut ldap) =
                Box::pin(LdapConnAsync::with_settings(self.settings.clone(), url)).await?;

            ldap3::drive!(conn);

            if let Some(bind) = &self.bind_dn {
                ldap.simple_bind(&bind.dn, &bind.password)
                    .await?
                    .success()?;
            } else if verify {
                ldap.extended(WhoAmI).await?;
            }

            Ok(ldap)
        })
        .await?
    }
}

macro_rules! with_conn {
    ($pool:expr, |$conn:ident| $operation:expr) => {{
        let pool = $pool;
        let mut conn = pool.get().await.map_err(|err| err.into_error())?;
        let result = {
            let $conn = &mut conn.ldap;
            $operation.await
        };
        match result {
            Err(err) if crate::backend::ldap::pool::is_transport_error(&err) => {
                trc::event!(
                    Store(trc::StoreEvent::LdapWarning),
                    Reason = "LDAP operation failed, retrying on a new connection",
                    CausedBy = err
                );
                drop(deadpool::managed::Object::take(conn));
                let mut conn = pool.get().await.map_err(|err| err.into_error())?;
                let $conn = &mut conn.ldap;
                $operation.await
            }
            result => result,
        }
    }};
}

pub(crate) use with_conn;

pub(crate) fn is_transport_error(err: &trc::Error) -> bool {
    err.matches(EventType::Store(StoreEvent::LdapError)) && err.value(Key::Code).is_none()
}
