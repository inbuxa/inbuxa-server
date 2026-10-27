/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::BlobStore;
use encodify::base32::STALWART;
use registry::schema::structs::{self, S3StoreRegion};
use s3::{
    Bucket, BucketConfig, Credentials, DeleteBatch, Endpoint, RetryPolicy, UrlStyle,
    delete::MAX_DELETE_KEYS,
};
use std::{ops::Range, sync::Arc};
use trc::StoreEvent;
use utils::http::http1_client_builder;

pub struct S3Store {
    bucket: Bucket,
    prefix: Option<Box<str>>,
    verify_after_write: bool,
}

impl S3Store {
    pub async fn open(config: structs::S3Store) -> Result<BlobStore, String> {
        let (region, endpoint) = region_endpoint(&config.region);
        let endpoint = Endpoint::parse(endpoint).map_err(|err| err.to_string())?;
        let credentials = Credentials::resolve(
            config.access_key_id.value().await?.as_deref(),
            config.secret_key.secret().await?.as_deref(),
            config.session_token.secret().await?.as_deref(),
            config.profile.as_deref(),
        )
        .map_err(|err| format!("Failed to create credentials: {err}"))?;
        let http = http1_client_builder(config.allow_invalid_certs)
            .timeout(config.timeout.into_inner())
            .build()
            .map_err(|err| format!("Failed to build the S3 HTTP client: {err}"))?;
        let bucket = Bucket::new(
            http,
            BucketConfig {
                endpoint,
                bucket: &config.bucket,
                region,
                style: UrlStyle::Path,
                credentials,
                retry: RetryPolicy::new(u32::try_from(config.max_retries).unwrap_or(u32::MAX)),
            },
        )
        .map_err(|err| format!("Failed to create bucket: {err}"))?;

        Ok(BlobStore::S3(Arc::new(S3Store {
            bucket,
            prefix: config.key_prefix.map(String::into_boxed_str),
            verify_after_write: config.verify_after_write,
        })))
    }

    pub async fn get_blob(&self, key: &[u8], range: Range<usize>) -> trc::Result<Option<Vec<u8>>> {
        let range = (range.start != 0 || range.end != usize::MAX)
            .then(|| range.start as u64..u64::try_from(range.end).unwrap_or(u64::MAX));
        self.bucket
            .get_object(&self.build_key(key), range)
            .await
            .map(|body| body.map(Vec::from))
            .map_err(into_error)
    }

    pub async fn put_blob(&self, key: &[u8], data: Vec<u8>) -> trc::Result<()> {
        let path = self.build_key(key);
        let data = bytes::Bytes::from(data);
        let sent_checksum = self.bucket.sends_checksum();
        let result = if self.verify_after_write {
            self.bucket.put_object_verified(&path, data).await
        } else {
            self.bucket.put_object(&path, data).await
        };
        if sent_checksum && !self.bucket.sends_checksum() {
            trc::event!(
                Store(StoreEvent::S3Error),
                Reason = "The S3 service refused the x-amz-checksum-crc32c header; uploads continue with Content-MD5",
            );
        }
        result.map_err(into_error)
    }

    pub async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        self.bucket
            .delete_object(&self.build_key(key))
            .await
            .map_err(into_error)
    }

    pub async fn delete_blobs(&self, keys: &[&[u8]]) -> trc::Result<()> {
        if !self.bucket.supports_multi_delete() {
            return self.delete_each(keys).await;
        }
        let key_len = self.key_len(keys.first().map_or(0, |key| key.len()));
        let mut path = String::with_capacity(key_len);
        for (index, chunk) in keys.chunks(MAX_DELETE_KEYS).enumerate() {
            let mut batch = DeleteBatch::with_capacity(chunk.len(), key_len);
            for key in chunk {
                path.clear();
                self.build_key_into(key, &mut path);
                batch.push(&path).map_err(into_error)?;
            }
            match self.bucket.delete_objects(batch).await {
                Ok(()) => {}
                Err(err) if err.is_not_implemented() => {
                    return self
                        .delete_each(keys.get(index * MAX_DELETE_KEYS..).unwrap_or_default())
                        .await;
                }
                Err(err) => return Err(into_error(err)),
            }
        }
        Ok(())
    }

    async fn delete_each(&self, keys: &[&[u8]]) -> trc::Result<()> {
        for key in keys {
            self.delete_blob(key).await?;
        }
        Ok(())
    }

    fn key_len(&self, key_len: usize) -> usize {
        self.prefix.as_ref().map_or(0, |prefix| prefix.len()) + STALWART.encoded_len(key_len)
    }

    fn build_key(&self, key: &[u8]) -> String {
        let mut out = String::with_capacity(self.key_len(key.len()));
        self.build_key_into(key, &mut out);
        out
    }

    fn build_key_into(&self, key: &[u8], out: &mut String) {
        if let Some(prefix) = &self.prefix {
            out.push_str(prefix);
        }
        STALWART.encode_append(key, out);
    }
}

fn region_endpoint(region: &S3StoreRegion) -> (&str, &str) {
    match region {
        S3StoreRegion::UsEast1 => ("us-east-1", "s3.us-east-1.amazonaws.com"),
        S3StoreRegion::UsEast2 => ("us-east-2", "s3.us-east-2.amazonaws.com"),
        S3StoreRegion::UsWest1 => ("us-west-1", "s3.us-west-1.amazonaws.com"),
        S3StoreRegion::UsWest2 => ("us-west-2", "s3.us-west-2.amazonaws.com"),
        S3StoreRegion::CaCentral1 => ("ca-central-1", "s3.ca-central-1.amazonaws.com"),
        S3StoreRegion::AfSouth1 => ("af-south-1", "s3.af-south-1.amazonaws.com"),
        S3StoreRegion::ApEast1 => ("ap-east-1", "s3.ap-east-1.amazonaws.com"),
        S3StoreRegion::ApSouth1 => ("ap-south-1", "s3.ap-south-1.amazonaws.com"),
        S3StoreRegion::ApNortheast1 => ("ap-northeast-1", "s3.ap-northeast-1.amazonaws.com"),
        S3StoreRegion::ApNortheast2 => ("ap-northeast-2", "s3.ap-northeast-2.amazonaws.com"),
        S3StoreRegion::ApNortheast3 => ("ap-northeast-3", "s3.ap-northeast-3.amazonaws.com"),
        S3StoreRegion::ApSoutheast1 => ("ap-southeast-1", "s3.ap-southeast-1.amazonaws.com"),
        S3StoreRegion::ApSoutheast2 => ("ap-southeast-2", "s3.ap-southeast-2.amazonaws.com"),
        S3StoreRegion::CnNorth1 => ("cn-north-1", "s3.cn-north-1.amazonaws.com.cn"),
        S3StoreRegion::CnNorthwest1 => ("cn-northwest-1", "s3.cn-northwest-1.amazonaws.com.cn"),
        S3StoreRegion::EuNorth1 => ("eu-north-1", "s3.eu-north-1.amazonaws.com"),
        S3StoreRegion::EuCentral1 => ("eu-central-1", "s3.eu-central-1.amazonaws.com"),
        S3StoreRegion::EuCentral2 => ("eu-central-2", "s3.eu-central-2.amazonaws.com"),
        S3StoreRegion::EuWest1 => ("eu-west-1", "s3.eu-west-1.amazonaws.com"),
        S3StoreRegion::EuWest2 => ("eu-west-2", "s3.eu-west-2.amazonaws.com"),
        S3StoreRegion::EuWest3 => ("eu-west-3", "s3.eu-west-3.amazonaws.com"),
        S3StoreRegion::IlCentral1 => ("il-central-1", "s3.il-central-1.amazonaws.com"),
        S3StoreRegion::MeSouth1 => ("me-south-1", "s3.me-south-1.amazonaws.com"),
        S3StoreRegion::SaEast1 => ("sa-east-1", "s3.sa-east-1.amazonaws.com"),
        S3StoreRegion::DoNyc3 => ("nyc3", "nyc3.digitaloceanspaces.com"),
        S3StoreRegion::DoAms3 => ("ams3", "ams3.digitaloceanspaces.com"),
        S3StoreRegion::DoSgp1 => ("sgp1", "sgp1.digitaloceanspaces.com"),
        S3StoreRegion::DoFra1 => ("fra1", "fra1.digitaloceanspaces.com"),
        S3StoreRegion::Yandex => ("ru-central1", "storage.yandexcloud.net"),
        S3StoreRegion::WaUsEast1 => ("us-east-1", "s3.us-east-1.wasabisys.com"),
        S3StoreRegion::WaUsEast2 => ("us-east-2", "s3.us-east-2.wasabisys.com"),
        S3StoreRegion::WaUsCentral1 => ("us-central-1", "s3.us-central-1.wasabisys.com"),
        S3StoreRegion::WaUsWest1 => ("us-west-1", "s3.us-west-1.wasabisys.com"),
        S3StoreRegion::WaCaCentral1 => ("ca-central-1", "s3.ca-central-1.wasabisys.com"),
        S3StoreRegion::WaEuCentral1 => ("eu-central-1", "s3.eu-central-1.wasabisys.com"),
        S3StoreRegion::WaEuCentral2 => ("eu-central-2", "s3.eu-central-2.wasabisys.com"),
        S3StoreRegion::WaEuWest1 => ("eu-west-1", "s3.eu-west-1.wasabisys.com"),
        S3StoreRegion::WaEuWest2 => ("eu-west-2", "s3.eu-west-2.wasabisys.com"),
        S3StoreRegion::WaApNortheast1 => ("ap-northeast-1", "s3.ap-northeast-1.wasabisys.com"),
        S3StoreRegion::WaApNortheast2 => ("ap-northeast-2", "s3.ap-northeast-2.wasabisys.com"),
        S3StoreRegion::WaApSoutheast1 => ("ap-southeast-1", "s3.ap-southeast-1.wasabisys.com"),
        S3StoreRegion::WaApSoutheast2 => ("ap-southeast-2", "s3.ap-southeast-2.wasabisys.com"),
        S3StoreRegion::Custom(custom) => (&custom.region, &custom.url),
    }
}

fn into_error(err: s3::Error) -> trc::Error {
    let error = StoreEvent::S3Error.reason(err.to_string());
    match err.status() {
        Some(status) => error.ctx(trc::Key::Code, status),
        None => error,
    }
}

