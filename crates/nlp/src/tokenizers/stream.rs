/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    language::{
        Language,
        detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
        stemmer::STEMMER_MAP,
        stopwords::{STOP_WORDS, StopwordFnc},
    },
    tokenizers::{chinese::JIEBA, japanese},
};
use std::borrow::Cow;

pub struct WordStemTokenizer {
    stemmer: Stemmer,
    stop_words: Option<StopwordFnc>,
}

enum Stemmer {
    IndoEuropean(rust_stemmers::Stemmer),
    Mandarin,
    Japanese,
    None,
}

impl WordStemTokenizer {
    pub fn new(text: &str) -> Self {
        // Detect language
        let (mut language, score) =
            LanguageDetector::detect_single(text).unwrap_or((Language::English, 1.0));
        if score < MIN_LANGUAGE_SCORE {
            language = Language::English;
        }

        Self {
            stemmer: match language {
                Language::Mandarin => Stemmer::Mandarin,
                Language::Japanese => Stemmer::Japanese,
                _ => STEMMER_MAP[language as usize]
                    .map(|algo| Stemmer::IndoEuropean(rust_stemmers::Stemmer::create(algo)))
                    .unwrap_or(Stemmer::None),
            },
            stop_words: STOP_WORDS[language as usize],
        }
    }

    pub fn tokenize<'x>(&self, word: &'x str, mut cb: impl FnMut(Cow<'x, str>)) {
        if self.stop_words.is_some_and(|sw| sw(word)) {
            return;
        }
        match &self.stemmer {
            Stemmer::IndoEuropean(stemmer) => {
                cb(stemmer.stem(word));
            }
            Stemmer::Mandarin => {
                for token in JIEBA.cut(word, false) {
                    cb(Cow::from(token.word));
                }
            }
            Stemmer::Japanese => {
                for word in japanese::tokenize(word) {
                    cb(Cow::from(word));
                }
            }
            Stemmer::None => {
                cb(Cow::from(word));
            }
        }
    }
}

