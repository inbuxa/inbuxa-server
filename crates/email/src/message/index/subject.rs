/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_parser::thread_name;
use std::{borrow::Cow, iter::once};

pub fn search_subject(subject: &str) -> Cow<'_, str> {
    let name = thread_name(subject);
    let Some(offset) = name.as_ptr().addr().checked_sub(subject.as_ptr().addr()) else {
        return Cow::Borrowed(name);
    };
    let Some((prefix, _)) = subject.split_at_checked(offset) else {
        return Cow::Borrowed(name);
    };
    let Some((markers, tail)) = prefix.rsplit_once(':') else {
        return Cow::Borrowed(subject.get(..offset + name.len()).map_or(name, str::trim));
    };
    let mut kept = markers
        .split(':')
        .filter_map(|segment| {
            segment
                .trim_end()
                .rsplit_once(char::is_whitespace)
                .map(|(words, _)| words.trim())
        })
        .chain(once(tail.trim()))
        .filter(|words| !words.is_empty())
        .peekable();
    if kept.peek().is_none() {
        return Cow::Borrowed(name);
    }
    let mut text = String::with_capacity(subject.len());
    for words in kept {
        text.push_str(words);
        text.push(' ');
    }
    text.push_str(name);
    Cow::Owned(text)
}

pub fn search_subject_query(text: &str) -> Cow<'_, str> {
    match search_subject(text) {
        subject if subject.is_empty() => Cow::Borrowed(text),
        subject => subject,
    }
}

