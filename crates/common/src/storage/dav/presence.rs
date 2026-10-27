/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use types::metadata::{MetadataKinds, MetadataView, XmlName};

pub const DISPLAY_NAME_PROPERTY: XmlName<'static> = XmlName::borrowed(Some("DAV:"), "displayname");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresenceBits {
    jmap: u16,
    dav: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct FilePresence(u16);

impl PresenceBits {
    pub const CALENDAR_EVENT: PresenceBits = PresenceBits::new(1 << 10, 1 << 4);
    pub const CONTACT_CARD: PresenceBits = PresenceBits::new(1 << 1, 1);
    pub const FILE_NODE: PresenceBits = PresenceBits::new(1, 1 << 1);

    const fn new(jmap: u16, dav: u16) -> Self {
        PresenceBits { jmap, dav }
    }

    pub const fn jmap(self) -> u16 {
        self.jmap
    }

    pub const fn dav(self) -> u16 {
        self.dav
    }

    pub const fn mask(self) -> u16 {
        self.jmap | self.dav
    }

    pub const fn kinds(self, flags: u16) -> MetadataKinds {
        let jmap = if flags & self.jmap != 0 {
            MetadataKinds::JMAP
        } else {
            MetadataKinds::NONE
        };
        let dav = if flags & self.dav != 0 {
            MetadataKinds::DAV
        } else {
            MetadataKinds::NONE
        };
        jmap.union(dav)
    }

    pub const fn apply(self, flags: u16, kinds: MetadataKinds) -> u16 {
        let mut flags = flags & !self.mask();
        if kinds.intersects(MetadataKinds::JMAP) {
            flags |= self.jmap;
        }
        if kinds.intersects(MetadataKinds::DAV) {
            flags |= self.dav;
        }
        flags
    }
}

impl FilePresence {
    pub const NONE: FilePresence = FilePresence(0);
    const DAV_DISPLAY_NAME: u16 = 1 << 2;
    pub(crate) const MASK: u16 = PresenceBits::FILE_NODE.mask() | Self::DAV_DISPLAY_NAME;

    pub const fn from_bits(bits: u16) -> Self {
        FilePresence(bits & Self::MASK)
    }

    pub const fn from_kinds(kinds: MetadataKinds) -> Self {
        FilePresence(PresenceBits::FILE_NODE.apply(0, kinds))
    }

    pub fn from_view(view: &MetadataView<'_>) -> Self {
        let kinds = view.kinds();
        let mut presence = if kinds.intersects(MetadataKinds::JMAP) {
            FilePresence::from_kinds(MetadataKinds::JMAP)
        } else {
            FilePresence::NONE
        };
        if kinds.intersects(MetadataKinds::DAV) {
            for (name, _) in view.dav() {
                if name == DISPLAY_NAME_PROPERTY {
                    presence = presence.with_dav_display_name();
                } else {
                    presence.0 |= PresenceBits::FILE_NODE.dav();
                }
            }
        }
        presence
    }

    pub const fn with_dav_display_name(self) -> Self {
        FilePresence(self.0 | Self::DAV_DISPLAY_NAME)
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn apply(self, flags: u16) -> u16 {
        (flags & !Self::MASK) | self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn has_dav_display_name(self) -> bool {
        self.0 & Self::DAV_DISPLAY_NAME != 0
    }

    pub const fn has_dead_properties(self) -> bool {
        self.0 & PresenceBits::FILE_NODE.dav() != 0
    }

    pub const fn kinds(self) -> MetadataKinds {
        let kinds = PresenceBits::FILE_NODE.kinds(self.0);
        if self.has_dav_display_name() {
            kinds.union(MetadataKinds::DAV)
        } else {
            kinds
        }
    }
}

