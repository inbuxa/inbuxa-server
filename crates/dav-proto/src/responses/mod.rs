/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod acl;
pub mod error;
pub mod lock;
pub mod mkcol;
pub mod multistatus;
pub mod property;
pub mod propstat;
pub mod schedule;

use crate::schema::{
    Namespaces,
    property::{Comp, ResourceType, SupportedCollation},
    response::{Href, List, Location, ResponseDescription, Status, SyncToken},
};
use std::fmt::{Display, Write};

trait XmlEscape {
    fn write_escaped_to(&self, out: &mut impl Write) -> std::fmt::Result;
}

trait XmlCdataEscape {
    fn write_cdata_escaped_to(&self, out: &mut impl Write) -> std::fmt::Result;
}

const CDATA_END: &[u8] = b"]]>";

impl<T: AsRef<str>> XmlEscape for T {
    fn write_escaped_to(&self, out: &mut impl Write) -> std::fmt::Result {
        let text = self.as_ref();
        let mut start = 0;

        for (pos, byte) in text.bytes().enumerate() {
            let entity = match byte {
                b'<' => "&lt;",
                b'>' => "&gt;",
                b'&' => "&amp;",
                b'"' => "&quot;",
                b'\'' => "&apos;",
                _ => continue,
            };
            out.write_str(text.get(start..pos).unwrap_or_default())?;
            out.write_str(entity)?;
            start = pos + 1;
        }

        out.write_str(text.get(start..).unwrap_or_default())
    }
}

impl<T: AsRef<str>> XmlCdataEscape for T {
    fn write_cdata_escaped_to(&self, out: &mut impl Write) -> std::fmt::Result {
        let text = self.as_ref();
        let mut start = 0;

        out.write_str("<![CDATA[")?;

        for pos in memchr::memmem::find_iter(text.as_bytes(), CDATA_END) {
            out.write_str(text.get(start..pos).unwrap_or_default())?;
            out.write_str("]]]]><![CDATA[>")?;
            start = pos + CDATA_END.len();
        }

        out.write_str(text.get(start..).unwrap_or_default())?;
        out.write_str("]]>")
    }
}

impl Display for Namespaces {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("xmlns:D=\"DAV:\"")?;
        if self.cal {
            f.write_str(" xmlns:A=\"urn:ietf:params:xml:ns:caldav\"")?;
        }
        if self.card {
            f.write_str(" xmlns:B=\"urn:ietf:params:xml:ns:carddav\"")?;
        }
        if self.cs {
            f.write_str(" xmlns:C=\"http://calendarserver.org/ns/\"")?;
        }
        Ok(())
    }
}

impl Display for Href {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:href>")?;
        self.0.write_escaped_to(f)?;
        write!(f, "</D:href>")
    }
}

impl<T: Display> Display for List<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for item in &self.0 {
            item.fmt(f)?;
        }

        Ok(())
    }
}

impl Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:status>")?;
        write!(f, "HTTP/1.1 {}", self.0)?;
        write!(f, "</D:status>")
    }
}

impl Display for ResponseDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:responsedescription>")?;
        self.0.write_escaped_to(f)?;
        write!(f, "</D:responsedescription>")
    }
}

impl Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:location>")?;
        self.0.fmt(f)?;
        write!(f, "</D:location>")
    }
}

impl Display for SyncToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:sync-token>")?;
        self.0.write_escaped_to(f)?;
        write!(f, "</D:sync-token>")
    }
}

impl Display for Comp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<A:comp name=\"{}\"/>", self.0.as_str())
    }
}

impl Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceType::Collection => write!(f, "<D:collection/>"),
            ResourceType::Principal => write!(f, "<D:principal/>"),
            ResourceType::AddressBook => write!(f, "<B:addressbook/>"),
            ResourceType::Calendar => write!(f, "<A:calendar/>"),
            ResourceType::ScheduleInbox => write!(f, "<A:schedule-inbox/>"),
            ResourceType::ScheduleOutbox => write!(f, "<A:schedule-outbox/>"),
        }
    }
}

impl Display for SupportedCollation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ns = self.namespace.prefix();
        write!(
            f,
            "<{ns}:supported-collation>{}</{ns}:supported-collation>",
            self.collation.as_str()
        )
    }
}

