/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Serialization of [`AggregateReport`] to RFC 9990 XML and to a complete
//! report email message.

use crate::{
    ReportEnvelope,
    dmarc::{
        AggregateReport, AuthResults, DateRange, Discovery, Disposition, DkimAuthResult,
        DkimStatus, DmarcStatus, Identifiers, PolicyEvaluated, PolicyOverride,
        PolicyOverrideReason, PolicyPublished, Record, ReportMetadata, Row, SpfAuthResult,
        SpfScope, SpfStatus,
    },
};
use flate2::{Compression, write::GzEncoder};
use mail_auth::dmarc::Policy;
use mail_builder::{MessageBuilder, headers::HeaderType, mime::make_boundary};
use std::{
    borrow::Cow,
    fmt::{Display, Formatter, Write},
    io,
};

impl AggregateReport {
    /// Writes the report as an RFC 5322 message to `writer`.
    ///
    /// The message has a `text/plain` summary and the output of
    /// [`to_xml`](Self::to_xml), gzip-compressed, as an `application/gzip`
    /// attachment named `submitter!domain!begin!end.xml.gz`. It carries an
    /// `Auto-Submitted: auto-generated` header field.
    ///
    /// Fields read from `envelope`:
    ///
    /// - `from`: the `From` header field.
    /// - `to`: the `To` header field.
    /// - `submitter`: the `Message-ID` host, the subject, the text body and
    ///   the file name.
    /// - `subject`: the subject; when `None`, defaults to
    ///   `Report Domain: <domain> Submitter: <submitter> Report-ID: <<report_id>>`.
    ///
    /// The Report Domain is always `policy_published.domain`;
    /// `envelope.report_domain` is ignored.
    ///
    /// # Errors
    ///
    /// Returns any I/O error raised by `writer` or by the gzip encoder.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use mail_auth::dmarc::Policy;
    /// use smtp_report::{
    ///     ReportEnvelope,
    ///     dmarc::{
    ///         AggregateReport, DateRange, Disposition, DmarcStatus, Identifiers,
    ///         PolicyEvaluated, PolicyPublished, Record, ReportMetadata, ReportVersion, Row,
    ///     },
    /// };
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let report = AggregateReport {
    ///     version: Some(ReportVersion::V1),
    ///     report_metadata: ReportMetadata {
    ///         org_name: "Example Inc.".into(),
    ///         email: "dmarc@example.net".into(),
    ///         report_id: "abc-123".into(),
    ///         date_range: DateRange {
    ///             begin: 1_700_000_000,
    ///             end: 1_700_086_400,
    ///         },
    ///         ..Default::default()
    ///     },
    ///     policy_published: PolicyPublished {
    ///         domain: "example.org".into(),
    ///         p: Policy::Reject,
    ///         ..Default::default()
    ///     },
    ///     records: vec![Record {
    ///         row: Row {
    ///             source_ip: Some("192.0.2.1".parse().expect("valid IP address")),
    ///             count: 3,
    ///             policy_evaluated: PolicyEvaluated {
    ///                 disposition: Disposition::Pass,
    ///                 dkim: DmarcStatus::Pass,
    ///                 spf: DmarcStatus::Fail,
    ///                 reason: vec![],
    ///             },
    ///         },
    ///         identifiers: Identifiers {
    ///             envelope_from: "example.org".into(),
    ///             header_from: "example.org".into(),
    ///             ..Default::default()
    ///         },
    ///         ..Default::default()
    ///     }],
    ///     ..Default::default()
    /// };
    ///
    /// let envelope = ReportEnvelope {
    ///     from: ("Example DMARC Reporter", "noreply-dmarc@example.net").into(),
    ///     to: vec!["dmarc-reports@example.org"],
    ///     submitter: "example.net",
    ///     report_domain: "",
    ///     subject: None,
    /// };
    ///
    /// report.write_rfc5322(&envelope, std::io::stdout())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn write_rfc5322(
        &self,
        envelope: &ReportEnvelope<'_>,
        writer: impl io::Write,
    ) -> io::Result<()> {
        let xml = self.to_xml();
        let mut e = GzEncoder::new(Vec::with_capacity(xml.len()), Compression::default());
        io::Write::write_all(&mut e, xml.as_bytes())?;
        let compressed_bytes = e.finish()?;

        let submitter = envelope.submitter;
        let domain = self.policy_published.domain.as_str();
        let report_id = self.report_metadata.report_id.as_str();
        let subject = envelope.subject.map_or_else(
            || {
                Cow::Owned(format!(
                    "Report Domain: {domain} Submitter: {submitter} Report-ID: <{report_id}>"
                ))
            },
            Cow::Borrowed,
        );

        MessageBuilder::new()
            .from(envelope.from.clone())
            .header("To", envelope.to_header())
            .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
            .message_id(format!("{}@{}", make_boundary("."), submitter))
            .subject(subject)
            .text_body(format!(
                concat!(
                    "DMARC aggregate report from {}\r\n\r\n",
                    "Report Domain: {}\r\n",
                    "Submitter: {}\r\n",
                    "Report-ID: {}\r\n",
                ),
                submitter, domain, submitter, report_id
            ))
            .attachment(
                "application/gzip",
                format!(
                    "{}!{}!{}!{}.xml.gz",
                    submitter,
                    domain,
                    self.report_metadata.date_range.begin,
                    self.report_metadata.date_range.end
                ),
                compressed_bytes,
            )
            .write_to(writer)
    }

    /// Returns the report as an RFC 5322 message.
    ///
    /// Same as [`write_rfc5322`](Self::write_rfc5322), collected into a
    /// `String`.
    ///
    /// # Errors
    ///
    /// Returns an error if the gzip encoder fails or the message is not valid
    /// UTF-8.
    pub fn to_rfc5322(&self, envelope: &ReportEnvelope<'_>) -> io::Result<String> {
        let mut buf = Vec::new();
        self.write_rfc5322(envelope, &mut buf)?;
        String::from_utf8(buf).map_err(io::Error::other)
    }

    /// Serializes the report as an RFC 9990 XML document in the
    /// `urn:ietf:params:xml:ns:dmarc-2.0` namespace.
    ///
    /// Optional elements are omitted when unset. The `version_published`
    /// element and all extensions are not written. Multiple `errors` are
    /// joined with `; ` into a single `error` element, and each record gets
    /// at most one `spf` result (see [`AuthResults::spf`]).
    pub fn to_xml(&self) -> String {
        let mut xml = String::with_capacity(128);
        writeln!(&mut xml, "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>").ok();
        writeln!(
            &mut xml,
            "<feedback xmlns=\"urn:ietf:params:xml:ns:dmarc-2.0\">"
        )
        .ok();
        if let Some(version) = self.version {
            writeln!(&mut xml, "\t<version>{}</version>", version.as_str()).ok();
        }
        self.report_metadata.to_xml(&mut xml);
        self.policy_published.to_xml(&mut xml);
        for record in &self.records {
            record.to_xml(&mut xml);
        }
        writeln!(&mut xml, "</feedback>").ok();
        xml
    }
}

impl ReportMetadata {
    pub(crate) fn to_xml(&self, xml: &mut String) {
        writeln!(xml, "\t<report_metadata>").ok();
        writeln!(
            xml,
            "\t\t<org_name>{}</org_name>",
            escape_xml(&self.org_name)
        )
        .ok();
        writeln!(xml, "\t\t<email>{}</email>", escape_xml(&self.email)).ok();
        if let Some(eci) = &self.extra_contact_info {
            writeln!(
                xml,
                "\t\t<extra_contact_info>{}</extra_contact_info>",
                escape_xml(eci)
            )
            .ok();
        }
        writeln!(
            xml,
            "\t\t<report_id>{}</report_id>",
            escape_xml(&self.report_id)
        )
        .ok();
        self.date_range.to_xml(xml);
        match self.errors.as_slice() {
            [] => {}
            [error] => {
                writeln!(xml, "\t\t<error>{}</error>", escape_xml(error)).ok();
            }
            errors => {
                writeln!(xml, "\t\t<error>{}</error>", escape_xml(&errors.join("; "))).ok();
            }
        }
        if let Some(generator) = &self.generator {
            writeln!(xml, "\t\t<generator>{}</generator>", escape_xml(generator)).ok();
        }
        writeln!(xml, "\t</report_metadata>").ok();
    }
}

impl PolicyPublished {
    pub(crate) fn to_xml(&self, xml: &mut String) {
        writeln!(xml, "\t<policy_published>").ok();
        writeln!(xml, "\t\t<domain>{}</domain>", escape_xml(&self.domain)).ok();
        writeln!(xml, "\t\t<p>{}</p>", self.p).ok();
        if self.sp != Policy::Unspecified {
            writeln!(xml, "\t\t<sp>{}</sp>", self.sp).ok();
        }
        if self.np != Policy::Unspecified {
            writeln!(xml, "\t\t<np>{}</np>", self.np).ok();
        }
        if let Some(adkim) = self.adkim {
            writeln!(xml, "\t\t<adkim>{adkim}</adkim>").ok();
        }
        if let Some(aspf) = self.aspf {
            writeln!(xml, "\t\t<aspf>{aspf}</aspf>").ok();
        }
        if self.discovery_method != Discovery::Unspecified {
            writeln!(
                xml,
                "\t\t<discovery_method>{}</discovery_method>",
                self.discovery_method
            )
            .ok();
        }
        if let Some(fo) = &self.fo {
            writeln!(xml, "\t\t<fo>{}</fo>", escape_xml(fo)).ok();
        }
        writeln!(
            xml,
            "\t\t<testing>{}</testing>",
            if self.testing { "y" } else { "n" }
        )
        .ok();
        writeln!(xml, "\t</policy_published>").ok();
    }
}

impl DateRange {
    pub(crate) fn to_xml(&self, xml: &mut String) {
        writeln!(xml, "\t\t<date_range>").ok();
        writeln!(xml, "\t\t\t<begin>{}</begin>", self.begin).ok();
        writeln!(xml, "\t\t\t<end>{}</end>", self.end).ok();
        writeln!(xml, "\t\t</date_range>").ok();
    }
}

impl Record {
    pub(crate) fn to_xml(&self, xml: &mut String) {
        writeln!(xml, "\t<record>").ok();
        self.row.to_xml(xml);
        self.identifiers.to_xml(xml);
        self.auth_results.to_xml(xml);
        writeln!(xml, "\t</record>").ok();
    }
}

impl Row {
    pub(crate) fn to_xml(&self, xml: &mut String) {
        writeln!(xml, "\t\t<row>").ok();
        if let Some(source_ip) = &self.source_ip {
            writeln!(xml, "\t\t\t<source_ip>{source_ip}</source_ip>").ok();
        }
        writeln!(xml, "\t\t\t<count>{}</count>", self.count).ok();
        self.policy_evaluated.to_xml(xml);
        writeln!(xml, "\t\t</row>").ok();
    }
}

impl PolicyEvaluated {
    pub(crate) fn to_xml(&self, xml: &mut String) {
        writeln!(xml, "\t\t\t<policy_evaluated>").ok();
        writeln!(
            xml,
            "\t\t\t\t<disposition>{}</disposition>",
            self.disposition
        )
        .ok();
        writeln!(xml, "\t\t\t\t<dkim>{}</dkim>", self.dkim).ok();
        writeln!(xml, "\t\t\t\t<spf>{}</spf>", self.spf).ok();
        for reason in &self.reason {
            reason.to_xml(xml);
        }
        writeln!(xml, "\t\t\t</policy_evaluated>").ok();
    }
}

impl PolicyOverrideReason {
    pub(crate) fn to_xml(&self, xml: &mut String) {
        writeln!(xml, "\t\t\t\t<reason>").ok();
        writeln!(xml, "\t\t\t\t\t<type>{}</type>", self.kind).ok();
        if let Some(comment) = &self.comment {
            writeln!(xml, "\t\t\t\t\t<comment>{}</comment>", escape_xml(comment)).ok();
        }
        writeln!(xml, "\t\t\t\t</reason>").ok();
    }
}

impl Identifiers {
    pub(crate) fn to_xml(&self, xml: &mut String) {
        writeln!(xml, "\t\t<identifiers>").ok();
        if let Some(envelope_to) = &self.envelope_to {
            writeln!(
                xml,
                "\t\t\t<envelope_to>{}</envelope_to>",
                escape_xml(envelope_to)
            )
            .ok();
        }
        writeln!(
            xml,
            "\t\t\t<envelope_from>{}</envelope_from>",
            escape_xml(&self.envelope_from)
        )
        .ok();
        writeln!(
            xml,
            "\t\t\t<header_from>{}</header_from>",
            escape_xml(&self.header_from)
        )
        .ok();
        writeln!(xml, "\t\t</identifiers>").ok();
    }
}

impl AuthResults {
    pub(crate) fn to_xml(&self, xml: &mut String) {
        writeln!(xml, "\t\t<auth_results>").ok();
        for dkim in &self.dkim {
            dkim.to_xml(xml);
        }
        if let Some(spf) = self.spf.iter().find(|spf| spf.scope != SpfScope::Helo) {
            spf.to_xml(xml);
        }
        writeln!(xml, "\t\t</auth_results>").ok();
    }
}

impl DkimAuthResult {
    pub(crate) fn to_xml(&self, xml: &mut String) {
        writeln!(xml, "\t\t\t<dkim>").ok();
        writeln!(xml, "\t\t\t\t<domain>{}</domain>", escape_xml(&self.domain)).ok();
        writeln!(
            xml,
            "\t\t\t\t<selector>{}</selector>",
            escape_xml(&self.selector)
        )
        .ok();
        writeln!(xml, "\t\t\t\t<result>{}</result>", self.result).ok();
        if let Some(result) = &self.human_result {
            writeln!(
                xml,
                "\t\t\t\t<human_result>{}</human_result>",
                escape_xml(result)
            )
            .ok();
        }
        writeln!(xml, "\t\t\t</dkim>").ok();
    }
}

impl SpfAuthResult {
    pub(crate) fn to_xml(&self, xml: &mut String) {
        writeln!(xml, "\t\t\t<spf>").ok();
        writeln!(xml, "\t\t\t\t<domain>{}</domain>", escape_xml(&self.domain)).ok();
        if self.scope == SpfScope::MailFrom {
            writeln!(xml, "\t\t\t\t<scope>{}</scope>", self.scope).ok();
        }
        writeln!(xml, "\t\t\t\t<result>{}</result>", self.result).ok();
        if let Some(result) = &self.human_result {
            writeln!(
                xml,
                "\t\t\t\t<human_result>{}</human_result>",
                escape_xml(result)
            )
            .ok();
        }
        writeln!(xml, "\t\t\t</spf>").ok();
    }
}

impl Display for Disposition {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Disposition::None | Disposition::Unspecified => "none",
            Disposition::Pass => "pass",
            Disposition::Quarantine => "quarantine",
            Disposition::Reject => "reject",
        })
    }
}

impl Display for DmarcStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DmarcStatus::Pass => "pass",
            DmarcStatus::Fail => "fail",
            DmarcStatus::Unspecified => "",
        })
    }
}

impl Display for PolicyOverride {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PolicyOverride::TrustedForwarder => "trusted_forwarder",
            PolicyOverride::MailingList => "mailing_list",
            PolicyOverride::LocalPolicy => "local_policy",
            PolicyOverride::PolicyTestMode => "policy_test_mode",
            PolicyOverride::Other => "other",
        })
    }
}

impl Display for Discovery {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Discovery::Psl => "psl",
            Discovery::Treewalk => "treewalk",
            Discovery::Unspecified => "",
        })
    }
}

impl Display for DkimStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DkimStatus::None => "none",
            DkimStatus::Pass => "pass",
            DkimStatus::Fail => "fail",
            DkimStatus::Policy => "policy",
            DkimStatus::Neutral => "neutral",
            DkimStatus::TempError => "temperror",
            DkimStatus::PermError => "permerror",
        })
    }
}

impl Display for SpfScope {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SpfScope::Helo => "helo",
            SpfScope::MailFrom | SpfScope::Unspecified => "mfrom",
        })
    }
}

impl Display for SpfStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SpfStatus::None => "none",
            SpfStatus::Neutral => "neutral",
            SpfStatus::Pass => "pass",
            SpfStatus::Fail => "fail",
            SpfStatus::SoftFail => "softfail",
            SpfStatus::TempError => "temperror",
            SpfStatus::PermError => "permerror",
        })
    }
}

fn escape_xml(text: &str) -> Cow<'_, str> {
    for ch in text.as_bytes() {
        if b"\"'<>&".contains(ch) {
            let mut escaped = String::with_capacity(text.len());
            for ch in text.chars() {
                match ch {
                    '"' => {
                        escaped.push_str("&quot;");
                    }
                    '\'' => {
                        escaped.push_str("&apos;");
                    }
                    '<' => {
                        escaped.push_str("&lt;");
                    }
                    '>' => {
                        escaped.push_str("&gt;");
                    }
                    '&' => {
                        escaped.push_str("&amp;");
                    }
                    _ => {
                        escaped.push(ch);
                    }
                }
            }

            return escaped.into();
        }
    }
    text.into()
}

