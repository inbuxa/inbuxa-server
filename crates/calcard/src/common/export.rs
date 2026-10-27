/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExportError {
    NotGroup,
    NoComponents,
    InvalidPatch {
        recurrence_id: String,
        pointer: String,
    },
    EmbeddedSizeExceeded {
        max: usize,
    },
    UnresolvedBlob {
        blob_id: String,
    },
}

impl Display for ExportError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportError::NotGroup => {
                f.write_str("the top-level object is not a JSCalendar Group or a JSContact Card")
            }
            ExportError::NoComponents => {
                f.write_str("the object has no entries that convert to a component")
            }
            ExportError::InvalidPatch {
                recurrence_id,
                pointer,
            } => write!(
                f,
                "the patch at recurrenceOverrides/{recurrence_id}/{pointer} does not apply"
            ),
            ExportError::EmbeddedSizeExceeded { max } => write!(
                f,
                "the embedded binaries exceed the maximum size of {max} bytes"
            ),
            ExportError::UnresolvedBlob { blob_id } => {
                write!(f, "the blobId {blob_id} could not be resolved")
            }
        }
    }
}

impl std::error::Error for ExportError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ImportError {
    BlobIdFailed,
}

impl Display for ImportError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::BlobIdFailed => {
                f.write_str("the blob id generator failed to store a binary")
            }
        }
    }
}

impl std::error::Error for ImportError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RejectedPatch {
    pub recurrence_id: String,
    pub pointer: String,
}

impl Display for RejectedPatch {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the patch at recurrenceOverrides/{}/{} does not apply",
            self.recurrence_id, self.pointer
        )
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct EmbeddedBudget {
    max: Option<usize>,
    left: usize,
    charged: AHashSet<(usize, u64)>,
}

impl EmbeddedBudget {
    pub(crate) fn new(max: Option<usize>) -> Self {
        Self {
            max,
            left: max.unwrap_or(usize::MAX),
            charged: AHashSet::new(),
        }
    }

    pub(crate) fn take(&mut self, data: &[u8]) -> Result<(), ExportError> {
        let Some(max) = self.max else {
            return Ok(());
        };
        let key = (data.len(), self.charged.hasher().hash_one(data));
        if !self.charged.insert(key) {
            return Ok(());
        }
        match self.left.checked_sub(data.len()) {
            Some(left) => {
                self.left = left;
                Ok(())
            }
            None => {
                self.left = 0;
                Err(ExportError::EmbeddedSizeExceeded { max })
            }
        }
    }
}
