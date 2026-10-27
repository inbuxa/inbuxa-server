/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

include!(concat!(env!("OUT_DIR"), "/locales.rs"));

const TRADITIONAL_CHINESE: [&str; 4] = ["hant", "tw", "hk", "mo"];

pub fn locale_or_default(name: &str) -> &'static Locale {
    if let Some(locale) = locale(name) {
        return locale;
    }

    let mut subtags = name.split(['_', '-']);
    let language = subtags.next().unwrap_or(name);

    if language.eq_ignore_ascii_case("zh")
        && subtags.any(|subtag| {
            TRADITIONAL_CHINESE
                .iter()
                .any(|variant| subtag.eq_ignore_ascii_case(variant))
        })
    {
        return &ZH_TW_LOCALES;
    }

    locale_by_language(language).unwrap_or(&EN_US_LOCALES)
}

