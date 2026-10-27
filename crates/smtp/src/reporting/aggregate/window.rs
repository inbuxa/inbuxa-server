/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DESCRIPTOR_PREFIX_LEN, ReportItem};
use crate::reporting::{
    dmarc::complete_dmarc_report, index::InternalReportIndex, tls::complete_tls_report,
};
use common::{Server, expr::Bump};
use registry::schema::{
    prelude::ObjectType,
    structs::{DmarcInternalReport, TlsInternalReport},
};
use store::{
    Deserialize, IterateParams, Subspace, U64_LEN,
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass, assert::AssertValue},
};
use trc::{AddContext, OutgoingReportEvent};

const DESCRIPTOR_PAGE: usize = 512;

struct Descriptor {
    key: Vec<u8>,
    value: Vec<u8>,
}

impl Descriptor {
    fn item_id(&self) -> Option<u64> {
        self.key
            .get(DESCRIPTOR_PREFIX_LEN..)
            .and_then(|key| key.first_chunk::<U64_LEN>())
            .map(|id| u64::from_be_bytes(*id))
    }

    fn clear(&self, batch: &mut BatchBuilder) {
        let class = ValueClass::Any(AnyClass {
            subspace: Subspace::ReportOut,
            key: self.key.clone(),
        });
        batch
            .assert_value(class.clone(), AssertValue::Some)
            .clear(class);
    }
}

pub async fn create_window_reports(
    server: &Server,
    object: ObjectType,
    window_end: u64,
) -> trc::Result<()> {
    let end = ReportItem::descriptor_bound(object, window_end.saturating_add(1));
    let mut from = ReportItem::descriptor_bound(object, 0);
    let mut page: Vec<Descriptor> = Vec::with_capacity(DESCRIPTOR_PAGE);
    let span_id = server.inner.data.span_id_gen.generate();
    let mut arena = Bump::new();

    loop {
        page.clear();
        server
            .store()
            .iterate(
                IterateParams::new(from.clone(), end.clone()).limit(DESCRIPTOR_PAGE),
                |key, value| {
                    page.push(Descriptor {
                        key: key.to_vec(),
                        value: value.to_vec(),
                    });
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        let is_last = page.len() < DESCRIPTOR_PAGE;
        let mut ready = page.as_slice();
        if !is_last
            && let Some(last_id) = page.last().and_then(Descriptor::item_id)
            && let Some(split) = page.iter().position(|d| d.item_id() == Some(last_id))
            && split > 0
        {
            ready = page.get(..split).unwrap_or_default();
        }

        let mut batch = BatchBuilder::new();
        for group in ready.chunk_by(|a, b| a.item_id() == b.item_id()) {
            match group {
                [descriptor] => {
                    if let Some(item_id) = descriptor.item_id() {
                        write_report(
                            server, object, item_id, descriptor, &mut batch, &mut arena, span_id,
                        )
                        .await;
                    }
                    descriptor.clear(&mut batch);
                }
                descriptors => {
                    if let Some(item_id) = descriptors.first().and_then(Descriptor::item_id) {
                        ReportItem::new(object, item_id).clear(&mut batch);
                        trc::event!(
                            OutgoingReport(OutgoingReportEvent::SubmissionError),
                            SpanId = span_id,
                            Id = item_id,
                            Total = descriptors.len(),
                            Details = "Aggregate report id collision, reports dropped",
                        );
                    }
                    for descriptor in descriptors {
                        descriptor.clear(&mut batch);
                    }
                }
            }
            batch.commit_point();
        }

        if !batch.is_empty() {
            server
                .store()
                .write_batch(&mut batch)
                .await
                .caused_by(trc::location!())?;
        }

        match ready.last() {
            Some(last) if !is_last => {
                let mut key = Vec::with_capacity(last.key.len() + 1);
                key.extend_from_slice(&last.key);
                key.push(0);
                from = AnyKey {
                    subspace: Subspace::ReportOut,
                    key,
                };
            }
            _ => return Ok(()),
        }
    }
}

async fn write_report(
    server: &Server,
    object: ObjectType,
    item_id: u64,
    descriptor: &Descriptor,
    batch: &mut BatchBuilder,
    arena: &mut Bump,
    span_id: u64,
) {
    let written = match object {
        ObjectType::DmarcInternalReport => {
            match DmarcInternalReport::deserialize(&descriptor.value) {
                Ok(mut report) => {
                    complete_dmarc_report(server, &mut report, arena, span_id).await;
                    report.write_header(batch, item_id);
                    true
                }
                Err(_) => false,
            }
        }
        ObjectType::TlsInternalReport => match TlsInternalReport::deserialize(&descriptor.value) {
            Ok(mut report) => {
                complete_tls_report(server, &mut report, arena, span_id).await;
                report.write_header(batch, item_id);
                true
            }
            Err(_) => false,
        },
        _ => false,
    };
    if !written {
        ReportItem::new(object, item_id).clear(batch);
        trc::error!(
            trc::Error::corrupted_key(
                &descriptor.key,
                descriptor.value.as_slice().into(),
                trc::location!()
            )
            .span_id(span_id)
            .details("Undecodable aggregate report descriptor")
        );
    }
}
