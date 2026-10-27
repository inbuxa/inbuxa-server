/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::Language;
use ahash::AHashMap;
use whatlang::{Lang, Script, detect, detect_script};

pub const MIN_LANGUAGE_SCORE: f64 = 0.6;
pub const MAX_LANGUAGE_SAMPLE: usize = 4 << 10;
const SAMPLE_WINDOWS: usize = 3;
const SAMPLE_WINDOW: usize = MAX_LANGUAGE_SAMPLE / SAMPLE_WINDOWS;

#[cfg(inbuxa_tests)]
pub static DETECT_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[derive(Debug)]
struct WeightedAverage {
    weight: usize,
    occurrences: usize,
    confidence: f64,
}

#[derive(Debug)]
pub struct LanguageDetector {
    lang_detected: AHashMap<Language, WeightedAverage>,
}

impl Default for LanguageDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl LanguageDetector {
    pub fn new() -> LanguageDetector {
        LanguageDetector {
            lang_detected: AHashMap::default(),
        }
    }

    pub fn detect(&mut self, text: &str, min_score: f64) -> Language {
        if let Some((language, confidence)) = LanguageDetector::detect_single(text) {
            let w = self
                .lang_detected
                .entry(language)
                .or_insert_with(|| WeightedAverage {
                    weight: 0,
                    confidence: 0.0,
                    occurrences: 0,
                });
            w.occurrences += 1;
            w.weight += text.len();
            w.confidence += confidence * text.len() as f64;
            if confidence < min_score {
                Language::Unknown
            } else {
                language
            }
        } else {
            Language::Unknown
        }
    }

    pub fn most_frequent_language(&self) -> Option<Language> {
        self.lang_detected
            .iter()
            .filter(|(l, _)| !matches!(l, Language::None))
            .max_by(|(_, a), (_, b)| {
                ((a.confidence / a.weight as f64) * a.occurrences as f64)
                    .partial_cmp(&((b.confidence / b.weight as f64) * b.occurrences as f64))
                    .unwrap_or(std::cmp::Ordering::Less)
            })
            .map(|(l, _)| *l)
    }

    pub fn detect_single(text: &str) -> Option<(Language, f64)> {
        #[cfg(inbuxa_tests)]
        DETECT_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut sample = String::new();
        if text.len() > MAX_LANGUAGE_SAMPLE {
            sample.reserve(MAX_LANGUAGE_SAMPLE + SAMPLE_WINDOWS);
            let tail = text.len() - SAMPLE_WINDOW;
            for start in [0, tail / 2, tail] {
                let start = text.floor_char_boundary(start);
                if let Some(window) =
                    text.get(start..text.floor_char_boundary(start + SAMPLE_WINDOW))
                {
                    sample.push_str(window);
                    sample.push('\n');
                }
            }
        }
        detect(if sample.is_empty() { text } else { &sample })
            .map(|info| (Language::from(info.lang()), info.confidence()))
    }

    pub(crate) fn detect_by_script(text: &str) -> Option<Language> {
        match detect_script(text)? {
            Script::Mandarin => detect(text).map(|info| info.lang()),
            script => match script.langs() {
                [lang] => Some(*lang),
                _ => None,
            },
        }
        .map(Language::from)
    }
}

impl From<Lang> for Language {
    fn from(lang: Lang) -> Self {
        match lang {
            Lang::Epo => Language::Esperanto,
            Lang::Eng => Language::English,
            Lang::Rus => Language::Russian,
            Lang::Cmn => Language::Mandarin,
            Lang::Spa => Language::Spanish,
            Lang::Por => Language::Portuguese,
            Lang::Ita => Language::Italian,
            Lang::Ben => Language::Bengali,
            Lang::Fra => Language::French,
            Lang::Deu => Language::German,
            Lang::Ukr => Language::Ukrainian,
            Lang::Kat => Language::Georgian,
            Lang::Ara => Language::Arabic,
            Lang::Hin => Language::Hindi,
            Lang::Jpn => Language::Japanese,
            Lang::Heb => Language::Hebrew,
            Lang::Yid => Language::Yiddish,
            Lang::Pol => Language::Polish,
            Lang::Amh => Language::Amharic,
            Lang::Jav => Language::Javanese,
            Lang::Kor => Language::Korean,
            Lang::Nob => Language::Bokmal,
            Lang::Dan => Language::Danish,
            Lang::Swe => Language::Swedish,
            Lang::Fin => Language::Finnish,
            Lang::Tur => Language::Turkish,
            Lang::Nld => Language::Dutch,
            Lang::Hun => Language::Hungarian,
            Lang::Ces => Language::Czech,
            Lang::Ell => Language::Greek,
            Lang::Bul => Language::Bulgarian,
            Lang::Bel => Language::Belarusian,
            Lang::Mar => Language::Marathi,
            Lang::Kan => Language::Kannada,
            Lang::Ron => Language::Romanian,
            Lang::Slv => Language::Slovene,
            Lang::Hrv => Language::Croatian,
            Lang::Srp => Language::Serbian,
            Lang::Mkd => Language::Macedonian,
            Lang::Lit => Language::Lithuanian,
            Lang::Lav => Language::Latvian,
            Lang::Est => Language::Estonian,
            Lang::Tam => Language::Tamil,
            Lang::Vie => Language::Vietnamese,
            Lang::Urd => Language::Urdu,
            Lang::Tha => Language::Thai,
            Lang::Guj => Language::Gujarati,
            Lang::Uzb => Language::Uzbek,
            Lang::Pan => Language::Punjabi,
            Lang::Aze => Language::Azerbaijani,
            Lang::Ind => Language::Indonesian,
            Lang::Tel => Language::Telugu,
            Lang::Pes => Language::Persian,
            Lang::Mal => Language::Malayalam,
            Lang::Ori => Language::Oriya,
            Lang::Mya => Language::Burmese,
            Lang::Nep => Language::Nepali,
            Lang::Sin => Language::Sinhalese,
            Lang::Khm => Language::Khmer,
            Lang::Tuk => Language::Turkmen,
            Lang::Aka => Language::Akan,
            Lang::Zul => Language::Zulu,
            Lang::Sna => Language::Shona,
            Lang::Afr => Language::Afrikaans,
            Lang::Lat => Language::Latin,
            Lang::Slk => Language::Slovak,
            Lang::Cat => Language::Catalan,
            Lang::Tgl => Language::Tagalog,
            Lang::Hye => Language::Armenian,
            _ => Language::Unknown,
        }
    }
}

