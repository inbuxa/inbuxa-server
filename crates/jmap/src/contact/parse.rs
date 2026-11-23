/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::blob::download::BlobDownload;
use calcard::{Entry, Parser, vcard::VCard};
use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::parse::{ParseRequest, ParseResponse},
    object::contact::ContactCard,
    request::{IntoValid, MaybeInvalid},
};
use jmap_tools::Value;
use types::{blob::BlobId, id::Id};
use utils::map::vec_map::VecMap;

pub trait ContactCardParse: Sync + Send {
    fn contact_card_parse(
        &self,
        request: ParseRequest<ContactCard>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<ParseResponse<ContactCard>>> + Send;
}

impl ContactCardParse for Server {
    async fn contact_card_parse(
        &self,
        request: ParseRequest<ContactCard>,
        access_token: &AccessToken,
    ) -> trc::Result<ParseResponse<ContactCard>> {
        if request.blob_ids.len() > self.core.jmap.contact_parse_max_items {
            return Err(trc::JmapEvent::RequestTooLarge.into_err());
        }
        let return_all_properties = request.properties.is_none();
        let properties = request
            .properties
            .map(|v| v.into_valid().collect::<Vec<_>>())
            .unwrap_or_default();

        let mut response = ParseResponse {
            account_id: request.account_id,
            parsed: VecMap::with_capacity(request.blob_ids.len()),
            not_parsable: vec![],
            not_found: vec![],
        };

        for blob_id in request.blob_ids.into_valid() {
            // Fetch raw message to parse
            let raw_vcard = match self.blob_download(&blob_id, access_token).await? {
                Some(raw_vcard) => raw_vcard,
                None => {
                    response.not_found.push(MaybeInvalid::Value(blob_id));
                    continue;
                }
            };
            let Some(vcards) = read_vcards(std::str::from_utf8(&raw_vcard).unwrap_or_default())
            else {
                response.not_parsable.push(blob_id);
                continue;
            };
            let mut cards = Vec::with_capacity(vcards.len());
            for vcard in vcards {
                let mut js_contact = vcard.into_jscontact::<Id, BlobId>();

                if !return_all_properties {
                    js_contact
                        .0
                        .as_object_mut()
                        .unwrap()
                        .as_mut_vec()
                        .retain(|(k, _)| k.as_property().is_some_and(|k| properties.contains(k)));
                }

                cards.push(js_contact.into_inner());
            }

            response.parsed.append(blob_id, Value::Array(cards));
        }

        Ok(response)
    }
}

/// Every vCard in a blob, in order. `None` when the blob holds none, or holds anything
/// that is not a vCard.
fn read_vcards(text: &str) -> Option<Vec<VCard>> {
    let mut parser = Parser::new(text);
    let mut vcards = Vec::new();
    loop {
        match parser.entry() {
            Entry::VCard(vcard) => vcards.push(vcard),
            Entry::Eof if !vcards.is_empty() => return Some(vcards),
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::read_vcards;

    #[test]
    fn reads_every_vcard_in_a_blob() {
        let blob = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:One\r\nEND:VCARD\r\n\
                    BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Two\r\nEND:VCARD\r\n\
                    BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Three\r\nEND:VCARD\r\n";
        let names = read_vcards(blob)
            .unwrap()
            .iter()
            .map(|vcard| {
                vcard
                    .property(&calcard::vcard::VCardProperty::Fn)
                    .and_then(|entry| entry.values.first())
                    .and_then(|value| value.as_text())
                    .unwrap_or_default()
                    .to_string()
            })
            .collect::<Vec<_>>();
        assert_eq!(names, ["One", "Two", "Three"]);
    }

    #[test]
    fn blob_without_vcards_is_not_parsable() {
        assert!(read_vcards("").is_none());
        assert!(read_vcards("this is not a contact\r\n").is_none());
        assert!(
            read_vcards(
                "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:One\r\nEND:VCARD\r\n\
                 BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n"
            )
            .is_none()
        );
    }
}
