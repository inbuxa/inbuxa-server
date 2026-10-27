/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::{
    schema::structs::{
        DmarcDkimResult, DmarcExtension, DmarcPolicyOverrideReason, DmarcReportRecord,
        DmarcSpfResult, TlsFailureDetails,
    },
    types::{EnumImpl, ipaddr::IpAddr, list::List},
};
use std::net::{Ipv4Addr, Ipv6Addr};
use utils::codec::leb128::{Leb128Reader, Leb128Writer};

const IP_NONE: u8 = 0;
const IP_V4: u8 = 4;
const IP_V6: u8 = 6;
const NIBBLE: u16 = 0x0F;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Detail {
    Full,
    Compact,
}

pub(crate) trait ReportRow: Sized {
    fn encode_row(&self, context: &str, writer: &mut RowWriter<'_>);
    fn decode_row(context: &str, reader: &mut RowReader<'_>) -> Option<Self>;
}

pub(crate) struct RowWriter<'x> {
    out: &'x mut Vec<u8>,
    detail: Detail,
}

pub(crate) struct RowReader<'x>(&'x [u8]);

impl<'x> RowWriter<'x> {
    pub(crate) fn new(out: &'x mut Vec<u8>, detail: Detail) -> Self {
        RowWriter { out, detail }
    }

    fn byte(&mut self, value: u8) {
        self.out.push(value);
    }

    fn id(&mut self, value: impl EnumImpl) {
        self.out
            .push(u8::try_from(value.to_id()).unwrap_or(u8::MAX));
    }

    fn len(&mut self, value: usize) {
        self.out.push_leb128(value);
    }

    fn str(&mut self, value: &str) {
        self.len(value.len());
        self.out.extend_from_slice(value.as_bytes());
    }

    fn opt(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.len(value.len() + 1);
                self.out.extend_from_slice(value.as_bytes());
            }
            None => self.out.push(0),
        }
    }

    fn human(&mut self, value: Option<&str>) {
        match self.detail {
            Detail::Full => self.opt(value),
            Detail::Compact => self.opt(None),
        }
    }

    fn same_or(&mut self, value: &str, reference: &str) {
        if value == reference {
            self.out.push(0);
        } else {
            self.opt(Some(value));
        }
    }

    fn ip(&mut self, value: Option<&IpAddr>) {
        match value.map(|ip| ip.0) {
            Some(std::net::IpAddr::V4(ip)) => {
                self.out.push(IP_V4);
                self.out.extend_from_slice(&ip.octets());
            }
            Some(std::net::IpAddr::V6(ip)) => {
                self.out.push(IP_V6);
                self.out.extend_from_slice(&ip.octets());
            }
            None => self.out.push(IP_NONE),
        }
    }
}

impl<'x> RowReader<'x> {
    pub(crate) fn new(bytes: &'x [u8]) -> Self {
        RowReader(bytes)
    }

    fn byte(&mut self) -> Option<u8> {
        let (byte, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(*byte)
    }

    fn id<T: EnumImpl>(&mut self) -> Option<T> {
        self.byte().and_then(|id| T::from_id(u16::from(id)))
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (array, rest) = self.0.split_first_chunk::<N>()?;
        self.0 = rest;
        Some(*array)
    }

    fn len(&mut self) -> Option<usize> {
        self.0.read_leb128()
    }

    fn count(&mut self) -> Option<usize> {
        self.len().map(|count| count.min(self.0.len()))
    }

    fn bytes(&mut self, len: usize) -> Option<&'x str> {
        let (bytes, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        std::str::from_utf8(bytes).ok()
    }

    fn str(&mut self) -> Option<String> {
        let len = self.len()?;
        self.bytes(len).map(str::to_string)
    }

    fn opt(&mut self) -> Option<Option<String>> {
        match self.len()? {
            0 => Some(None),
            len => self.bytes(len - 1).map(|value| Some(value.to_string())),
        }
    }

    fn same_or(&mut self, reference: &str) -> Option<String> {
        self.opt()
            .map(|value| value.unwrap_or_else(|| reference.to_string()))
    }

    fn ip(&mut self) -> Option<Option<IpAddr>> {
        match self.byte()? {
            IP_V4 => Some(Some(IpAddr(Ipv4Addr::from(self.array::<4>()?).into()))),
            IP_V6 => Some(Some(IpAddr(Ipv6Addr::from(self.array::<16>()?).into()))),
            IP_NONE => Some(None),
            _ => None,
        }
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl ReportRow for DmarcReportRecord {
    fn encode_row(&self, domain: &str, writer: &mut RowWriter<'_>) {
        writer.id(self.evaluated_disposition);
        writer.byte(
            u8::try_from(
                ((self.evaluated_dkim.to_id() & NIBBLE) << 4)
                    | (self.evaluated_spf.to_id() & NIBBLE),
            )
            .unwrap_or(u8::MAX),
        );
        writer.ip(self.source_ip.as_ref());
        writer.same_or(&self.header_from, domain);
        writer.same_or(&self.envelope_from, &self.header_from);
        writer.opt(self.envelope_to.as_deref());
        writer.len(self.policy_override_reasons.len());
        for reason in self.policy_override_reasons.iter() {
            writer.id(reason.override_type);
            writer.human(reason.comment.as_deref());
        }
        writer.len(self.dkim_results.len());
        for dkim in self.dkim_results.iter() {
            writer.same_or(&dkim.domain, &self.header_from);
            writer.str(&dkim.selector);
            writer.id(dkim.result);
            writer.human(dkim.human_result.as_deref());
        }
        writer.len(self.spf_results.len());
        for spf in self.spf_results.iter() {
            writer.same_or(&spf.domain, &self.envelope_from);
            writer.id(spf.scope);
            writer.id(spf.result);
            writer.human(spf.human_result.as_deref());
        }
        writer.len(self.extensions.len());
        for extension in self.extensions.iter() {
            writer.str(&extension.name);
            writer.str(&extension.definition);
        }
    }

    fn decode_row(domain: &str, reader: &mut RowReader<'_>) -> Option<Self> {
        let evaluated_disposition = reader.id()?;
        let evaluations = u16::from(reader.byte()?);
        let source_ip = reader.ip()?;
        let header_from = reader.same_or(domain)?;
        let envelope_from = reader.same_or(&header_from)?;
        let envelope_to = reader.opt()?;

        let count = reader.count()?;
        let mut policy_override_reasons = List::with_capacity(count);
        for _ in 0..count {
            policy_override_reasons.push_unchecked(DmarcPolicyOverrideReason {
                override_type: reader.id()?,
                comment: reader.opt()?,
            });
        }
        let count = reader.count()?;
        let mut dkim_results = List::with_capacity(count);
        for _ in 0..count {
            dkim_results.push_unchecked(DmarcDkimResult {
                domain: reader.same_or(&header_from)?,
                selector: reader.str()?,
                result: reader.id()?,
                human_result: reader.opt()?,
            });
        }
        let count = reader.count()?;
        let mut spf_results = List::with_capacity(count);
        for _ in 0..count {
            spf_results.push_unchecked(DmarcSpfResult {
                domain: reader.same_or(&envelope_from)?,
                scope: reader.id()?,
                result: reader.id()?,
                human_result: reader.opt()?,
            });
        }
        let count = reader.count()?;
        let mut extensions = List::with_capacity(count);
        for _ in 0..count {
            extensions.push_unchecked(DmarcExtension {
                name: reader.str()?,
                definition: reader.str()?,
            });
        }

        reader.is_empty().then_some(DmarcReportRecord {
            source_ip,
            count: 0,
            evaluated_disposition,
            evaluated_dkim: EnumImpl::from_id(evaluations >> 4)?,
            evaluated_spf: EnumImpl::from_id(evaluations & NIBBLE)?,
            policy_override_reasons,
            envelope_to,
            envelope_from,
            header_from,
            dkim_results,
            spf_results,
            extensions,
        })
    }
}

impl ReportRow for TlsFailureDetails {
    fn encode_row(&self, _: &str, writer: &mut RowWriter<'_>) {
        writer.id(self.result_type);
        writer.ip(self.sending_mta_ip.as_ref());
        writer.ip(self.receiving_ip.as_ref());
        writer.opt(self.receiving_mx_hostname.as_deref());
        writer.opt(self.receiving_mx_helo.as_deref());
        writer.human(self.failure_reason_code.as_deref());
        writer.human(self.additional_information.as_deref());
    }

    fn decode_row(_: &str, reader: &mut RowReader<'_>) -> Option<Self> {
        let failure = TlsFailureDetails {
            result_type: reader.id()?,
            sending_mta_ip: reader.ip()?,
            receiving_ip: reader.ip()?,
            receiving_mx_hostname: reader.opt()?,
            receiving_mx_helo: reader.opt()?,
            failure_reason_code: reader.opt()?,
            additional_information: reader.opt()?,
            failed_session_count: 0,
        };
        reader.is_empty().then_some(failure)
    }
}

