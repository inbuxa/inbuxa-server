/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use unicode_normalization::UnicodeNormalization;

const GREEK_TITLECASE_OFFSET: u32 = 8;

pub fn unicode_casemap(text: &str, out: &mut String) {
    if text.is_ascii() {
        let start = out.len();
        out.push_str(text);
        if let Some(appended) = out.get_mut(start..) {
            appended.make_ascii_uppercase();
        }
    } else {
        out.extend(text.chars().map(simple_titlecase).nfkd());
    }
}

fn simple_titlecase(ch: char) -> char {
    match ch {
        '\u{01C4}'..='\u{01C6}' => '\u{01C5}',
        '\u{01C7}'..='\u{01C9}' => '\u{01C8}',
        '\u{01CA}'..='\u{01CC}' => '\u{01CB}',
        '\u{01F1}'..='\u{01F3}' => '\u{01F2}',
        '\u{10D0}'..='\u{10FA}' | '\u{10FD}'..='\u{10FF}' => ch,
        '\u{1F80}'..='\u{1F87}' | '\u{1F90}'..='\u{1F97}' | '\u{1FA0}'..='\u{1FA7}' => {
            char::from_u32(u32::from(ch) + GREEK_TITLECASE_OFFSET).unwrap_or(ch)
        }
        '\u{1FB3}' => '\u{1FBC}',
        '\u{1FC3}' => '\u{1FCC}',
        '\u{1FF3}' => '\u{1FFC}',
        _ => {
            let mut upper = ch.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(upper), None) => upper,
                _ => ch,
            }
        }
    }
}

