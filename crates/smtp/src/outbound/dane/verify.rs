/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

// inbuxa: the check itself is in inbuxa-outbound-tls, shared with
// inbuxa-relay (RL-30); this adds the queue's errors and trace events.

use crate::queue::{Error, ErrorDetails, HostResponse, Status};
use common::config::smtp::resolver::Tlsa;
use inbuxa_outbound_tls::dane::{self, DaneFailure};
use rustls_pki_types::CertificateDer;
use trc::DaneEvent;

pub trait TlsaVerify {
    fn verify(
        &self,
        session_id: u64,
        hostname: &str,
        reference_ids: &[&str],
        certificates: Option<&[CertificateDer<'_>]>,
    ) -> Result<(), Status<HostResponse<Box<str>>, ErrorDetails>>;
}

impl TlsaVerify for Tlsa {
    fn verify(
        &self,
        session_id: u64,
        hostname: &str,
        reference_ids: &[&str],
        certificates: Option<&[CertificateDer<'_>]>,
    ) -> Result<(), Status<HostResponse<Box<str>>, ErrorDetails>> {
        match dane::verify(self, reference_ids, certificates) {
            Ok(matched) => {
                trc::event!(
                    Dane(DaneEvent::TlsaRecordMatch),
                    SpanId = session_id,
                    Hostname = hostname.to_string(),
                    Type = matched.as_str(),
                );
                trc::event!(
                    Dane(DaneEvent::AuthenticationSuccess),
                    SpanId = session_id,
                    Hostname = hostname.to_string(),
                );

                Ok(())
            }
            Err(failure) => {
                match &failure {
                    DaneFailure::NoCertificates => trc::event!(
                        Dane(DaneEvent::NoCertificatesFound),
                        SpanId = session_id,
                        Hostname = hostname.to_string(),
                    ),
                    DaneFailure::CertificateParse(reason) => trc::event!(
                        Dane(DaneEvent::CertificateParseError),
                        SpanId = session_id,
                        Hostname = hostname.to_string(),
                        Reason = reason.clone(),
                    ),
                    DaneFailure::NoMatch => trc::event!(
                        Dane(DaneEvent::AuthenticationFailure),
                        SpanId = session_id,
                        Hostname = hostname.to_string(),
                    ),
                }

                Err(Status::TemporaryFailure(ErrorDetails {
                    entity: hostname.into(),
                    details: Error::DaneError(failure.description().into()),
                }))
            }
        }
    }
}
