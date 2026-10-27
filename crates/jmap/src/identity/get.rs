/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::StoredIdentities;
use crate::changes::state::StateManager;
use common::{Server, storage::index::ObjectIndexBuilder};
use email::identity::{ArchivedEmailAddress, Identity};
use jmap_proto::{
    method::get::{GetRequest, GetResponse, all_ids},
    object::identity::{self, IdentityProperty, IdentityValue},
};
use jmap_tools::{Map, Value};
use std::{collections::BTreeSet, future::Future};
use store::{
    SerializeInfallible, ValueKey,
    rkyv::{option::ArchivedOption, vec::ArchivedVec},
    write::{BatchBuilder, assert::AssertValue},
    xxhash_rust::xxh3::Xxh3,
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::{Field, PrincipalField},
};

pub trait IdentityGet: Sync + Send {
    fn identity_get(
        &self,
        request: GetRequest<identity::Identity>,
    ) -> impl Future<Output = trc::Result<GetResponse<identity::Identity>>> + Send;

    fn identity_get_or_create(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<StoredIdentities>> + Send;

    fn identities(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<StoredIdentities>> + Send;
}

impl IdentityGet for Server {
    async fn identity_get(
        &self,
        mut request: GetRequest<identity::Identity>,
    ) -> trc::Result<GetResponse<identity::Identity>> {
        let (ids, not_found_ids) = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            IdentityProperty::Id,
            IdentityProperty::Name,
            IdentityProperty::Email,
            IdentityProperty::ReplyTo,
            IdentityProperty::Bcc,
            IdentityProperty::TextSignature,
            IdentityProperty::HtmlSignature,
            IdentityProperty::MayDelete,
        ]);
        let account_id = request.account_id.document_id();
        let identities = self.identity_get_or_create(account_id).await?;
        let ids = if let Some(ids) = ids {
            ids
        } else {
            all_ids(
                identities.iter().map(|(document_id, _)| document_id.into()),
                self.core.jmap.get_max_objects,
            )?
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: self
                .get_state(account_id, SyncCollection::Identity)
                .await?
                .into(),
            list: Vec::with_capacity(ids.len()),
            not_found: not_found_ids,
        };

        for id in ids {
            // Obtain the identity object
            let Some(identity) = identities.get(id.document_id()) else {
                response.push_not_found(id);
                continue;
            };
            let identity = identity
                .unarchive::<Identity>()
                .caused_by(trc::location!())?;
            let mut result = Map::with_capacity(properties.len());
            for property in &properties {
                match property {
                    IdentityProperty::Id => {
                        result.insert_unchecked(IdentityProperty::Id, IdentityValue::Id(id));
                    }
                    IdentityProperty::MayDelete => {
                        result.insert_unchecked(IdentityProperty::MayDelete, Value::Bool(true));
                    }
                    IdentityProperty::Name => {
                        result.insert_unchecked(IdentityProperty::Name, identity.name.to_string());
                    }
                    IdentityProperty::Email => {
                        result
                            .insert_unchecked(IdentityProperty::Email, identity.email.to_string());
                    }
                    IdentityProperty::TextSignature => {
                        result.insert_unchecked(
                            IdentityProperty::TextSignature,
                            identity.text_signature.to_string(),
                        );
                    }
                    IdentityProperty::HtmlSignature => {
                        result.insert_unchecked(
                            IdentityProperty::HtmlSignature,
                            identity.html_signature.to_string(),
                        );
                    }
                    IdentityProperty::Bcc => {
                        result
                            .insert_unchecked(IdentityProperty::Bcc, email_to_value(&identity.bcc));
                    }
                    IdentityProperty::ReplyTo => {
                        result.insert_unchecked(
                            IdentityProperty::ReplyTo,
                            email_to_value(&identity.reply_to),
                        );
                    }
                    property => {
                        result.insert_unchecked(property.clone(), Value::Null);
                    }
                }
            }
            response.list.push(result.into());
        }

        Ok(response)
    }

    async fn identity_get_or_create(&self, account_id: u32) -> trc::Result<StoredIdentities> {
        // Obtain account info
        let account_info = self
            .account_info(account_id)
            .await
            .caused_by(trc::location!())?;
        let addresses = account_info
            .addresses()
            .iter()
            .map(|a| a.as_str())
            .collect::<BTreeSet<_>>();

        let mut hasher = Xxh3::new();
        for address in &addresses {
            hasher.update(address.as_bytes());
            hasher.update(b"\n");
        }
        let addresses_hash = hasher.digest();
        let stored_hash = self
            .store()
            .get_value::<u64>(ValueKey::property(
                account_id,
                Collection::Principal,
                0,
                PrincipalField::IdentityAddresses,
            ))
            .await
            .caused_by(trc::location!())?;
        let identities = self.identities(account_id).await?;

        if stored_hash == Some(addresses_hash) {
            return Ok(identities);
        }

        // Determine which addresses are missing and which identities are no longer valid
        let member_of = &account_info.account().id_member_of;
        let mut missing_addresses = addresses.clone();
        let mut obsolete = Vec::new();
        for (document_id, archive) in identities.iter() {
            let identity = archive
                .to_unarchived::<Identity>()
                .caused_by(trc::location!())?;
            let email = identity.inner.email.as_str();

            if addresses.contains(email) {
                missing_addresses.remove(email);
            } else if !self
                .account_id_from_email(email, true)
                .await
                .caused_by(trc::location!())?
                .is_some_and(|id| id == account_id || member_of.contains(&id))
            {
                obsolete.push((document_id, identity));
            }
        }

        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Identity);

        // Create identities for the new addresses
        if !missing_addresses.is_empty() {
            let name = account_info.description().unwrap_or(account_info.name());
            let slots = batch.reserve_document_ids(
                account_id,
                Collection::Identity,
                missing_addresses.len() as u32,
            );
            for (email, slot) in missing_addresses.into_iter().zip(slots.iter()) {
                let name = if name.is_empty() {
                    email.to_string()
                } else {
                    name.to_string()
                };
                batch
                    .create_document(slot)
                    .custom(ObjectIndexBuilder::<(), _>::new().with_changes(Identity {
                        name,
                        email: email.to_string(),
                        ..Default::default()
                    }))
                    .caused_by(trc::location!())?
                    .commit_point();
            }
        }

        // Delete identities whose address no longer belongs to this account
        for (document_id, identity) in obsolete {
            batch
                .with_document(document_id)
                .custom(ObjectIndexBuilder::<_, ()>::new().with_current(identity))
                .caused_by(trc::location!())?
                .commit_point();
        }

        batch
            .with_collection(Collection::Principal)
            .with_document(0)
            .assert_value(
                PrincipalField::IdentityAddresses,
                stored_hash.map_or(AssertValue::None, AssertValue::U64),
            )
            .set(
                PrincipalField::IdentityAddresses,
                addresses_hash.serialize(),
            );

        match self.commit_batch(batch).await {
            Ok(_) => {}
            Err(err) if err.is_assertion_failure() => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }

        self.identities(account_id).await
    }

    async fn identities(&self, account_id: u32) -> trc::Result<StoredIdentities> {
        let mut identities = StoredIdentities::default();
        self.archives(
            account_id,
            Collection::Identity,
            Field::ARCHIVE,
            &(),
            |document_id, archive| {
                identities.push(document_id, archive);
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| identities)
    }
}

fn email_to_value(
    email: &ArchivedOption<ArchivedVec<ArchivedEmailAddress>>,
) -> Value<'static, IdentityProperty, IdentityValue> {
    if let ArchivedOption::Some(email) = email {
        Value::Array(
            email
                .iter()
                .map(|email| {
                    Value::Object(
                        Map::with_capacity(2)
                            .with_key_value(IdentityProperty::Name, &email.name)
                            .with_key_value(IdentityProperty::Email, &email.email),
                    )
                })
                .collect(),
        )
    } else {
        Value::Null
    }
}
