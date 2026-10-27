/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod shared_key;

use crate::BlobStore;
use azure_core::{
    cloud::CloudConfiguration,
    credentials::{Secret, TokenCredential},
    http::{
        ClientOptions, ExponentialRetryOptions, RequestContent, RetryOptions, StatusCode,
        Transport, Url, headers::HeaderName,
    },
    time::Duration as SdkDuration,
};
use azure_identity::{
    ClientAssertionCredentialOptions, ClientSecretCredential, ClientSecretCredentialOptions,
    ManagedIdentityCredential, ManagedIdentityCredentialOptions, UserAssignedId,
    WorkloadIdentityCredential, WorkloadIdentityCredentialOptions,
};
use azure_storage_blob::{
    BlobClient, BlobContainerClient, BlobContainerClientOptions,
    models::{BlobClientDownloadOptions, HttpRange},
};
use encodify::base32::STALWART;
use futures::StreamExt;
use registry::schema::{
    enums::AzureEnvironment,
    structs::{self, AzureAuth},
};
use shared_key::SharedKeyPolicy;
use std::{fmt::Display, ops::Range, path::PathBuf, sync::Arc, time::Duration};
use utils::http::http_client_builder;

const CONTENT_RANGE: HeaderName = HeaderName::from_static("content-range");
const RETRY_MAX_DELAY: Duration = Duration::from_secs(30);
const MAX_PREALLOCATION: usize = 64 * 1024 * 1024;

pub struct AzureStore {
    client: BlobContainerClient,
    #[cfg(stalwart_tests)]
    container: BlobContainerClient,
    prefix: Option<Box<str>>,
}

impl AzureStore {
    pub async fn open(config: structs::AzureStore) -> Result<BlobStore, String> {
        validate_account(&config.storage_account)?;
        validate_container(&config.container)?;
        let mut container_url = container_url(
            config.url.as_deref(),
            &config.storage_account,
            &config.container,
            config.environment,
        )?;
        let uses_token_credential = !matches!(
            config.auth,
            AzureAuth::SharedKey(_) | AzureAuth::SasToken(_)
        );
        if uses_token_credential && container_url.scheme() != "https" {
            return Err(format!(
                "Azure Entra ID authentication requires an https URL, got {container_url}"
            ));
        }

        let http_client = http_client_builder(false)
            .timeout(config.timeout.into_inner())
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .build()
            .map_err(|err| format!("Failed to build Azure HTTP client: {err}"))?;
        let mut client_options = ClientOptions {
            transport: Some(Transport::new(Arc::new(http_client))),
            ..Default::default()
        };
        let credential_options = ClientOptions {
            cloud: cloud_configuration(config.environment).map(Arc::new),
            ..client_options.clone()
        };
        client_options.retry = retry_options(config.timeout.into_inner(), config.max_retries);

        let credential: Option<Arc<dyn TokenCredential>> = match config.auth {
            AzureAuth::SharedKey(auth) => {
                let account_key = auth.account_key.secret().await?;
                client_options
                    .per_try_policies
                    .push(Arc::new(SharedKeyPolicy::new(
                        &config.storage_account,
                        &account_key,
                    )?));
                None
            }
            AzureAuth::SasToken(auth) => {
                let sas_token = auth.sas_token.secret().await?;
                let sas_token = sas_token.trim();
                let sas_token = sas_token.strip_prefix('?').unwrap_or(sas_token);
                if sas_token.is_empty() {
                    return Err("Azure SAS token is empty".to_string());
                }
                container_url.set_query(Some(sas_token));
                None
            }
            AzureAuth::ClientSecret(auth) => Some(
                ClientSecretCredential::new(
                    &auth.tenant_id,
                    auth.client_id,
                    Secret::new(auth.client_secret.secret().await?.into_owned()),
                    Some(ClientSecretCredentialOptions {
                        client_options: credential_options,
                    }),
                )
                .map_err(|err| format!("Failed to create Azure client secret credential: {err}"))?,
            ),
            AzureAuth::ManagedIdentity(auth) => Some(
                ManagedIdentityCredential::new(Some(ManagedIdentityCredentialOptions {
                    user_assigned_id: auth.client_id.map(UserAssignedId::ClientId),
                    client_options: credential_options,
                }))
                .map_err(|err| {
                    format!("Failed to create Azure managed identity credential: {err}")
                })?,
            ),
            AzureAuth::WorkloadIdentity(auth) => Some(
                WorkloadIdentityCredential::new(Some(WorkloadIdentityCredentialOptions {
                    credential_options: ClientAssertionCredentialOptions {
                        client_options: credential_options,
                    },
                    client_id: auth.client_id,
                    tenant_id: auth.tenant_id,
                    token_file_path: auth.token_file.map(PathBuf::from),
                }))
                .map_err(|err| {
                    format!("Failed to create Azure workload identity credential: {err}")
                })?,
            ),
        };

        let (directory, prefix) = split_prefix(config.key_prefix.as_deref().unwrap_or_default());
        let blobs_url = blobs_url(&container_url, directory)?;
        let options = BlobContainerClientOptions {
            client_options,
            ..Default::default()
        };

        Ok(BlobStore::Azure(Arc::new(AzureStore {
            #[cfg(stalwart_tests)]
            container: BlobContainerClient::new(
                container_url,
                credential.clone(),
                Some(options.clone()),
            )
            .map_err(|err| format!("Failed to create Azure container client: {err}"))?,
            client: BlobContainerClient::new(blobs_url, credential, Some(options))
                .map_err(|err| format!("Failed to create Azure container client: {err}"))?,
            prefix: (!prefix.is_empty()).then(|| prefix.into()),
        })))
    }

    pub async fn get_blob(&self, key: &[u8], range: Range<usize>) -> trc::Result<Option<Vec<u8>>> {
        let blob_client = self.client.blob_client(&self.build_key(key));

        let http_range = match (range.start, range.end) {
            (0, usize::MAX) => None,
            (start, usize::MAX) => Some(HttpRange::from_offset(start as u64)),
            (start, end) if start < end => Some(HttpRange::new(start as u64, (end - start) as u64)),
            _ => return empty_range(&blob_client).await,
        };

        let result = match blob_client
            .download(Some(BlobClientDownloadOptions {
                range: http_range,
                ..Default::default()
            }))
            .await
        {
            Ok(result) => result,
            Err(err) => {
                return match err.http_status() {
                    Some(StatusCode::NotFound) => Ok(None),
                    Some(StatusCode::RequestedRangeNotSatisfiable) => Ok(Some(Vec::new())),
                    _ => Err(into_error(err)),
                };
            }
        };

        let total_len = result
            .headers
            .get_optional_str(&CONTENT_RANGE)
            .and_then(|value| value.rsplit_once('/'))
            .and_then(|(_, total)| total.parse::<usize>().ok())
            .or_else(|| {
                result
                    .properties
                    .content_length
                    .and_then(|len| usize::try_from(len).ok())
            })
            .unwrap_or_default();
        let mut buf = Vec::with_capacity(
            total_len
                .min(range.end)
                .saturating_sub(range.start)
                .min(MAX_PREALLOCATION),
        );
        let mut body = result.body;
        while let Some(chunk) = body.next().await {
            buf.extend_from_slice(&chunk.map_err(into_error)?);
        }

        Ok(Some(buf))
    }

    pub async fn put_blob(&self, key: &[u8], data: Vec<u8>) -> trc::Result<()> {
        self.client
            .blob_client(&self.build_key(key))
            .upload(RequestContent::from(data), None)
            .await
            .map(|_| ())
            .map_err(into_error)
    }

    pub async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        match self
            .client
            .blob_client(&self.build_key(key))
            .delete(None)
            .await
        {
            Ok(_) => Ok(true),
            Err(err) if err.http_status() == Some(StatusCode::NotFound) => Ok(false),
            Err(err) => Err(into_error(err)),
        }
    }

    fn build_key(&self, key: &[u8]) -> String {
        if let Some(prefix) = &self.prefix {
            let mut out = String::with_capacity(prefix.len() + STALWART.encoded_len(key.len()));
            out.push_str(prefix);
            STALWART.encode_append(key, &mut out);
            out
        } else {
            STALWART.encode(key)
        }
    }
}

async fn empty_range(blob_client: &BlobClient) -> trc::Result<Option<Vec<u8>>> {
    blob_client
        .exists()
        .await
        .map(|exists| exists.then(Vec::new))
        .map_err(into_error)
}

fn validate_account(account: &str) -> Result<(), String> {
    if (3..=24).contains(&account.len())
        && account
            .bytes()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
    {
        Ok(())
    } else {
        Err(format!(
            "Invalid Azure storage account name {account:?}: expected 3 to 24 lowercase letters or digits"
        ))
    }
}

fn validate_container(container: &str) -> Result<(), String> {
    let bytes = container.as_bytes();
    let is_alnum = |ch: &u8| ch.is_ascii_lowercase() || ch.is_ascii_digit();
    if (3..=63).contains(&bytes.len())
        && bytes.first().is_some_and(is_alnum)
        && bytes.last().is_some_and(is_alnum)
        && bytes.iter().all(|ch| is_alnum(ch) || *ch == b'-')
        && !bytes.windows(2).any(|pair| pair == b"--")
    {
        Ok(())
    } else {
        Err(format!(
            "Invalid Azure container name {container:?}: expected 3 to 63 lowercase letters, digits or single hyphens"
        ))
    }
}

fn container_url(
    url: Option<&str>,
    account: &str,
    container: &str,
    environment: AzureEnvironment,
) -> Result<Url, String> {
    let mut container_url = match url {
        Some(url) => Url::parse(url).map_err(|err| format!("Invalid Azure URL {url:?}: {err}"))?,
        None => Url::parse(&format!(
            "https://{account}.{}",
            endpoint_suffix(environment)
        ))
        .map_err(|err| format!("Invalid Azure storage account name: {err}"))?,
    };
    container_url
        .path_segments_mut()
        .map_err(|_| "Azure URL cannot be used as a base URL".to_string())?
        .pop_if_empty()
        .push(container);
    Ok(container_url)
}

fn split_prefix(prefix: &str) -> (&str, &str) {
    prefix.rsplit_once('/').unwrap_or(("", prefix))
}

fn blobs_url(container_url: &Url, directory: &str) -> Result<Url, String> {
    let mut url = container_url.clone();
    url.path_segments_mut()
        .map_err(|_| "Azure URL cannot be used as a base URL".to_string())?
        .extend(directory.split('/').filter(|segment| !segment.is_empty()));
    Ok(url)
}

fn endpoint_suffix(environment: AzureEnvironment) -> &'static str {
    match environment {
        AzureEnvironment::Public => "blob.core.windows.net",
        AzureEnvironment::China => "blob.core.chinacloudapi.cn",
        AzureEnvironment::UsGovernment => "blob.core.usgovcloudapi.net",
    }
}

fn cloud_configuration(environment: AzureEnvironment) -> Option<CloudConfiguration> {
    match environment {
        AzureEnvironment::Public => None,
        AzureEnvironment::China => Some(CloudConfiguration::AzureChina),
        AzureEnvironment::UsGovernment => Some(CloudConfiguration::AzureGovernment),
    }
}

fn retry_options(timeout: Duration, max_retries: u64) -> RetryOptions {
    let max_retries = u32::try_from(max_retries).unwrap_or(u32::MAX);
    if max_retries == 0 {
        return RetryOptions::none();
    }
    let attempts = max_retries.saturating_add(1);
    let max_total_elapsed = timeout
        .saturating_add(RETRY_MAX_DELAY)
        .saturating_mul(attempts);
    RetryOptions::exponential(ExponentialRetryOptions {
        max_retries,
        max_total_elapsed: SdkDuration::try_from(max_total_elapsed).unwrap_or(SdkDuration::MAX),
        max_delay: SdkDuration::try_from(RETRY_MAX_DELAY).unwrap_or(SdkDuration::MAX),
        ..Default::default()
    })
}

#[cold]
fn into_error(err: impl Display) -> trc::Error {
    trc::StoreEvent::AzureError.reason(err)
}

