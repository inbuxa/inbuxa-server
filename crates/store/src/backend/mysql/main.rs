/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{MysqlStore, into_error};
use crate::{
    backend::mysql::MysqlSearchField,
    search::{
        CalendarSearchField, ContactSearchField, EmailSearchField, SearchableField,
        TracingSearchField,
    },
    *,
};
use ::registry::schema::structs;
use mysql_async::{
    Conn, OptsBuilder, Pool, PoolConstraints, PoolOpts, SslOpts, prelude::Queryable,
};

impl MysqlStore {
    pub async fn open(config: structs::MySqlStore) -> Result<Store, String> {
        // inbuxa: ST-15: where the primary is, to tell a replica from it
        let primary_location = (config.host.clone(), config.port as u16, config.database.clone());
        let mut opts = OptsBuilder::default()
            .ip_or_hostname(config.host)
            .user(config.auth_username)
            .pass(config.auth_secret.secret().await?.map(|v| v.into_owned()))
            .db_name(Some(config.database))
            .max_allowed_packet(config.max_allowed_packet.map(|v| v as usize))
            .wait_timeout(config.timeout.map(|t| t.as_secs() as usize))
            .client_found_rows(true)
            .tcp_port(config.port as u16);

        if config.use_tls {
            opts = opts.ssl_opts(Some(
                SslOpts::default()
                    .with_danger_accept_invalid_certs(config.allow_invalid_certs)
                    .with_danger_skip_domain_validation(config.allow_invalid_certs),
            ));
        }

        // Configure connection pool
        let mut pool_min = PoolConstraints::default().min();
        let mut pool_max = PoolConstraints::default().max();
        if let Some(n_size) = config.pool_min_connections {
            pool_min = n_size as usize;
        }
        if let Some(n_size) = config.pool_max_connections {
            pool_max = n_size as usize;
        }
        opts = opts.pool_opts(
            PoolOpts::default().with_constraints(PoolConstraints::new(pool_min, pool_max).unwrap()),
        );

        // inbuxa: ST-5 to ST-15: each replica inherits the primary's settings
        // except where it is and how to sign in
        let mut replicas = vec![];
        for replica in config.read_replicas {
            replicas.push(crate::backend::scaleout::replica::Replica::new(
                Store::MySQL(Arc::new(MysqlStore {
                    conn_pool: Pool::new(
                        opts.clone()
                            .ip_or_hostname(replica.host.clone())
                            .user(replica.auth_username)
                            .pass(replica.auth_secret.secret().await?.map(|v| v.into_owned()))
                            .db_name(Some(replica.database.clone()))
                            .tcp_port(replica.port as u16),
                    ),
                })),
                replica.host,
                replica.port as u16,
                replica.database,
            ));
        }

        let primary = Store::MySQL(Arc::new(MysqlStore {
            conn_pool: Pool::new(opts),
        }));

        // ST-1: no replicas, no change
        if replicas.is_empty() {
            return Ok(primary);
        }
        Ok(Store::Replicated(
            crate::backend::scaleout::replica::ReplicatedStore::new(
                primary,
                primary_location,
                replicas,
                crate::backend::scaleout::replica::ReplicaKind::MySql,
            ),
        ))
    }

    pub(crate) async fn create_storage_tables(&self) -> trc::Result<()> {
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;

        for table in [
            SUBSPACE_ACL,
            SUBSPACE_TASK_QUEUE,
            SUBSPACE_DELETED_ITEMS,
            SUBSPACE_SPAM_SAMPLES,
            crate::SUBSPACE_INBUXA, // inbuxa: masked email
            SUBSPACE_BLOB_LINK,
            SUBSPACE_IN_MEMORY_VALUE,
            SUBSPACE_PROPERTY,
            SUBSPACE_REGISTRY,
            SUBSPACE_REGISTRY_PK,
            SUBSPACE_DIRECTORY,
            SUBSPACE_QUEUE_MESSAGE,
            SUBSPACE_QUEUE_EVENT,
            SUBSPACE_REPORT_OUT,
            SUBSPACE_REPORT_IN,
            SUBSPACE_LOGS,
            SUBSPACE_TELEMETRY_SPAN,
            SUBSPACE_TELEMETRY_METRIC,
        ] {
            let table = char::from(table);
            conn.query_drop(format!(
                "CREATE TABLE IF NOT EXISTS {table} (
                    k VARBINARY(255) NOT NULL,
                    v MEDIUMBLOB NOT NULL,
                    PRIMARY KEY (k)
                ) ENGINE=InnoDB"
            ))
            .await
            .map_err(into_error)?;
        }

        conn.query_drop(format!(
            "CREATE TABLE IF NOT EXISTS {} (
                k VARBINARY(255) NOT NULL,
                v LONGBLOB NOT NULL,
                PRIMARY KEY (k)
            ) ENGINE=InnoDB",
            char::from(SUBSPACE_BLOBS),
        ))
        .await
        .map_err(into_error)?;

        for table in [SUBSPACE_INDEXES, SUBSPACE_REGISTRY_IDX] {
            let table = char::from(table);
            conn.query_drop(format!(
                "CREATE TABLE IF NOT EXISTS {table} (
                    k BLOB,
                    PRIMARY KEY (k(400))
                ) ENGINE=InnoDB"
            ))
            .await
            .map_err(into_error)?;
        }

        for table in [SUBSPACE_COUNTER, SUBSPACE_QUOTA, SUBSPACE_IN_MEMORY_COUNTER] {
            conn.query_drop(format!(
                "CREATE TABLE IF NOT EXISTS {} (
                k VARBINARY(255) NOT NULL,
                v BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (k)
            ) ENGINE=InnoDB",
                char::from(table)
            ))
            .await
            .map_err(into_error)?;
        }

        Ok(())
    }

    pub(crate) async fn create_search_tables(&self) -> trc::Result<()> {
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;

        create_search_tables::<EmailSearchField>(&mut conn).await?;
        create_search_tables::<CalendarSearchField>(&mut conn).await?;
        create_search_tables::<ContactSearchField>(&mut conn).await?;
        //create_search_tables::<FileSearchField>(&mut conn).await?;
        create_search_tables::<TracingSearchField>(&mut conn).await?;

        Ok(())
    }
}

async fn create_search_tables<T: SearchableField + MysqlSearchField + 'static>(
    conn: &mut Conn,
) -> trc::Result<()> {
    let table_name = T::index().mysql_table();
    let mut query = format!("CREATE TABLE IF NOT EXISTS {} (", table_name);

    // Add primary key columns
    let pkeys = T::primary_keys();
    for pkey in pkeys {
        query.push_str(&format!("{} {}, ", pkey.column(), pkey.column_type()));
    }

    // Add other columns
    for field in T::all_fields() {
        query.push_str(&format!("{} {}, ", field.column(), field.column_type()));
    }

    // Add primary key constraint
    query.push_str("PRIMARY KEY (");
    for (i, pkey) in pkeys.iter().enumerate() {
        if i > 0 {
            query.push_str(", ");
        }
        query.push_str(pkey.column());
    }
    query.push_str(")) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    conn.query_drop(&query).await.map_err(into_error)?;

    // Create indexes
    for field in T::all_fields() {
        if field.is_text() {
            let column_name = field.column();
            let create_index_query = format!(
                "CREATE FULLTEXT INDEX fts_{table_name}_{column_name} ON {table_name}({column_name})",
            );

            let _ = conn.query_drop(&create_index_query).await;
        }

        if field.is_indexed() {
            let column_name = field.column();
            let create_index_query = format!(
                "CREATE INDEX idx_{table_name}_{column_name} ON {table_name}({column_name})",
            );
            let _ = conn.query_drop(&create_index_query).await;
        }
    }

    Ok(())
}
