/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    error::set::{SetError, SetErrorType},
    object::email::EmailProperty,
};
use mail_parser::Message;
use std::fmt::Display;
use types::keyword::Keyword;

pub const MAX_HEADER_ENTRIES: usize = 65_534;
const HEADER_TERMINATOR_LEN: usize = b"\r\n".len();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmailLimits {
    pub mailboxes_per_email: usize,
    pub keywords_per_email: usize,
    pub keyword_length: usize,
    pub header_count: usize,
    pub header_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailLimitError {
    TooManyMailboxes { max: usize },
    TooManyKeywords { max: usize },
    KeywordTooLong { max: usize },
    TooManyHeaders { max: usize },
    TooManyMessageHeaders { max: usize },
    HeaderTooLarge { max: usize },
}

impl EmailLimits {
    pub fn validate_mailbox_count(&self, count: usize) -> Result<(), EmailLimitError> {
        if count <= self.mailboxes_per_email {
            Ok(())
        } else {
            Err(EmailLimitError::TooManyMailboxes {
                max: self.mailboxes_per_email,
            })
        }
    }

    pub fn validate_mailbox_change(
        &self,
        prev_count: usize,
        count: usize,
    ) -> Result<(), EmailLimitError> {
        if count <= prev_count {
            Ok(())
        } else {
            self.validate_mailbox_count(count)
        }
    }

    pub fn validate_keyword_count(&self, count: usize) -> Result<(), EmailLimitError> {
        if count <= self.keywords_per_email {
            Ok(())
        } else {
            Err(EmailLimitError::TooManyKeywords {
                max: self.keywords_per_email,
            })
        }
    }

    pub fn validate_keyword_change(
        &self,
        prev_count: usize,
        count: usize,
    ) -> Result<(), EmailLimitError> {
        if count <= prev_count {
            Ok(())
        } else {
            self.validate_keyword_count(count)
        }
    }

    pub fn validate_keyword_names<'x>(
        &self,
        names: impl IntoIterator<Item = &'x str>,
    ) -> Result<(), EmailLimitError> {
        if names
            .into_iter()
            .all(|name| name.len() <= self.keyword_length)
        {
            Ok(())
        } else {
            Err(EmailLimitError::KeywordTooLong {
                max: self.keyword_length,
            })
        }
    }

    pub fn validate_keywords<'x>(
        &self,
        count: usize,
        names: impl IntoIterator<Item = &'x str>,
    ) -> Result<(), EmailLimitError> {
        self.validate_keyword_count(count)?;
        self.validate_keyword_names(names)
    }

    pub fn validate_email(
        &self,
        mailbox_count: usize,
        keywords: &[Keyword],
    ) -> Result<(), EmailLimitError> {
        self.validate_mailbox_count(mailbox_count)?;
        self.validate_keywords(
            keywords.len(),
            keywords.iter().filter_map(|keyword| keyword.id().err()),
        )
    }

    pub fn is_keyword_allowed(&self, keyword: &Keyword) -> bool {
        keyword
            .id()
            .map_or_else(|name| name.len() <= self.keyword_length, |_| true)
    }

    pub fn header_fields_size(&self) -> usize {
        self.header_size.saturating_sub(HEADER_TERMINATOR_LEN)
    }

    pub fn validate_header_section(&self, message: &Message<'_>) -> Result<(), EmailLimitError> {
        let root = message.root_part();
        if root.headers().len() > self.header_count {
            Err(EmailLimitError::TooManyHeaders {
                max: self.header_count,
            })
        } else if message.header_count() > MAX_HEADER_ENTRIES {
            Err(EmailLimitError::TooManyMessageHeaders {
                max: MAX_HEADER_ENTRIES,
            })
        } else if root.offset_body().saturating_sub(root.offset_header()) as usize
            > self.header_size
        {
            Err(EmailLimitError::HeaderTooLarge {
                max: self.header_size,
            })
        } else {
            Ok(())
        }
    }
}

impl From<EmailLimitError> for SetError<EmailProperty> {
    fn from(err: EmailLimitError) -> Self {
        match err {
            EmailLimitError::TooManyMailboxes { .. } => {
                SetError::new(SetErrorType::TooManyMailboxes)
                    .with_property(EmailProperty::MailboxIds)
            }
            EmailLimitError::TooManyKeywords { .. } => {
                SetError::new(SetErrorType::TooManyKeywords).with_property(EmailProperty::Keywords)
            }
            EmailLimitError::KeywordTooLong { .. } => {
                SetError::invalid_properties().with_property(EmailProperty::Keywords)
            }
            EmailLimitError::TooManyHeaders { .. }
            | EmailLimitError::TooManyMessageHeaders { .. }
            | EmailLimitError::HeaderTooLarge { .. } => SetError::too_large(),
        }
        .with_description(err.to_string())
    }
}

impl Display for EmailLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmailLimitError::TooManyMailboxes { max } => {
                write!(f, "An email cannot belong to more than {max} mailboxes.")
            }
            EmailLimitError::TooManyKeywords { max } => {
                write!(f, "An email cannot have more than {max} keywords.")
            }
            EmailLimitError::KeywordTooLong { max } => {
                write!(f, "Keywords cannot be longer than {max} bytes.")
            }
            EmailLimitError::TooManyHeaders { max } => {
                write!(f, "An email header cannot have more than {max} fields.")
            }
            EmailLimitError::TooManyMessageHeaders { max } => {
                write!(
                    f,
                    "An email cannot have more than {max} header fields across all its parts."
                )
            }
            EmailLimitError::HeaderTooLarge { max } => {
                write!(f, "An email header cannot exceed {max} bytes.")
            }
        }
    }
}

