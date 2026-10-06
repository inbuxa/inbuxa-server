/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: what an install from before the rename carries over (SPEC.md
//! §2.4). The web interface's OAuth client is retired rather than kept as an
//! alias, and a trained spam filter moves to its new keys.

use crate::utils::server::TestServerBuilder;
use common::manager::{SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY, first_party::WEB_INTERFACE_CLIENT_ID};
use registry::{
    schema::{
        enums::CompressionAlgo,
        prelude::{ObjectType, Property},
        structs::{Application, OAuthClient},
    },
    types::map::Map,
};

const OLD_CLIENT_ID: &str = "stalwart-webui";
const OLD_TRAINER_KEY: &[u8] = b"STALWART_SPAM_TRAIN_DATA.lz4";
const OLD_CLASSIFIER_KEY: &[u8] = b"STALWART_SPAM_CLASSIFIER_MODEL.lz4";

#[tokio::test(flavor = "multi_thread")]
async fn renamed_identifiers() {
    // The web interface registered under upstream's client id, and an
    // application naming it. Disabled, so nothing is fetched for it.
    let test = TestServerBuilder::new("renamed_identifiers")
        .await
        .with_object(OAuthClient {
            client_id: OLD_CLIENT_ID.to_string(),
            redirect_uris: Map::new(vec!["https://127.0.0.1/admin/oauth/callback".to_string()]),
            ..Default::default()
        })
        .await
        .with_object(Application {
            enabled: false,
            description: "Web interface".to_string(),
            resource_url: "https://127.0.0.1/webui.zip".to_string(),
            url_prefix: Map::new(vec!["/admin".to_string()]),
            oauth_client_id: Some(OLD_CLIENT_ID.to_string()),
            ..Default::default()
        })
        .await
        .disable_services()
        .build()
        .await;

    println!("Running renamed identifier tests...");
    let registry = test.server.registry();
    assert_eq!(
        registry
            .primary_key(
                ObjectType::OAuthClient.into(),
                Property::ClientId,
                OLD_CLIENT_ID.as_bytes().to_vec(),
            )
            .await
            .unwrap(),
        None,
        "the pre-rename web interface client is retired on start"
    );
    let applications = registry.list::<Application>().await.unwrap();
    assert_eq!(applications.len(), 1);
    assert_eq!(
        applications[0].object.oauth_client_id.as_deref(),
        Some(WEB_INTERFACE_CLIENT_ID),
        "an application naming the old client moves to the new one"
    );

    // A trained model under the pre-rename keys moves to the new ones.
    let blobs = test.server.blob_store();
    for (key, data) in [
        (OLD_TRAINER_KEY, &b"trainer"[..]),
        (OLD_CLASSIFIER_KEY, &b"classifier"[..]),
    ] {
        blobs.put_blob(key, data, CompressionAlgo::None).await.unwrap();
    }
    migration::try_migrate(&test.server).await.unwrap();
    for (old, new, data) in [
        (OLD_TRAINER_KEY, SPAM_TRAINER_KEY, &b"trainer"[..]),
        (OLD_CLASSIFIER_KEY, SPAM_CLASSIFIER_KEY, &b"classifier"[..]),
    ] {
        assert_eq!(blobs.get_blob(new, 0..usize::MAX).await.unwrap().as_deref(), Some(data));
        assert_eq!(blobs.get_blob(old, 0..usize::MAX).await.unwrap(), None);
    }

    // A blob already under the new key wins over a stale old one.
    blobs
        .put_blob(OLD_CLASSIFIER_KEY, b"stale", CompressionAlgo::None)
        .await
        .unwrap();
    migration::try_migrate(&test.server).await.unwrap();
    assert_eq!(
        blobs
            .get_blob(SPAM_CLASSIFIER_KEY, 0..usize::MAX)
            .await
            .unwrap()
            .as_deref(),
        Some(&b"classifier"[..])
    );
    assert_eq!(blobs.get_blob(OLD_CLASSIFIER_KEY, 0..usize::MAX).await.unwrap(), None);

    // With nothing left to move, starting again changes nothing.
    migration::try_migrate(&test.server).await.unwrap();
    assert_eq!(
        blobs.get_blob(SPAM_TRAINER_KEY, 0..usize::MAX).await.unwrap().as_deref(),
        Some(&b"trainer"[..])
    );
}
