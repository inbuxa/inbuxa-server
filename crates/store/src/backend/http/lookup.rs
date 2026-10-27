/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{HttpStore, HttpStoreConfig};
use crate::{Value, backend::http::HttpStoreFormat, write::now};
use ahash::AHashMap;
use compact_str::ToCompactString;
use rand::seq::IndexedRandom;
use std::{
    borrow::Cow,
    io::{self, BufRead, BufReader, Read},
    sync::{Arc, atomic::Ordering},
    time::Instant,
};
use utils::HttpLimitResponse;

const BROWSER_USER_AGENTS: [&str; 5] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
];

pub(crate) trait HttpStoreGet {
    fn get(&self, key: &str) -> Option<Value<'static>>;
    fn contains(&self, key: &str) -> bool;
    fn refresh(&self);
}

impl HttpStoreGet for Arc<HttpStore> {
    fn get(&self, key: &str) -> Option<Value<'static>> {
        self.refresh();
        self.entries.load().get(lookup_key(key).as_ref()).cloned()
    }

    fn contains(&self, key: &str) -> bool {
        #[cfg(stalwart_tests)]
        {
            if self.config.url.contains("phishtank.com")
                || self.config.url.contains("openphish.com")
            {
                return (self.config.url.contains("open") && key.contains("open"))
                    || (self.config.url.contains("tank") && key.contains("tank"));
            } else if self.config.url.contains("disposable.github.io") {
                return key.ends_with("guerrillamail.com") || key.ends_with("disposable.org");
            } else if self.config.url.contains("free_email_provider_domains.txt") {
                return key.ends_with("gmail.com")
                    || key.ends_with("googlemail.com")
                    || key.ends_with("yahoomail.com")
                    || key.ends_with("outlook.com")
                    || key.ends_with("freemail.org");
            }
        }

        self.refresh();
        self.entries.load().contains_key(lookup_key(key).as_ref())
    }

    fn refresh(&self) {
        if self.expires.load(Ordering::Relaxed) <= now() {
            let in_flight = self.in_flight.swap(true, Ordering::Relaxed);
            if !in_flight {
                let this = self.clone();
                tokio::spawn(async move {
                    let expires = match this.try_refresh().await {
                        Ok(list) => {
                            this.entries.store(list.into());
                            this.config.refresh_interval
                        }
                        Err(err) => {
                            trc::error!(err);
                            this.config.retry
                        }
                    };

                    this.expires.store(now() + expires, Ordering::Relaxed);
                    this.in_flight.store(false, Ordering::Relaxed);
                });
            }
        }
    }
}

impl HttpStore {
    async fn try_refresh(&self) -> trc::Result<AHashMap<String, Value<'static>>> {
        let time = Instant::now();
        let mut request = self
            .client
            .get(&self.config.url)
            .timeout(self.config.timeout);
        if !self.config.custom_user_agent
            && let Some(agent) = BROWSER_USER_AGENTS.choose(&mut rand::rng())
        {
            request = request.header(reqwest::header::USER_AGENT, *agent);
        }
        let response = request.send().await.map_err(|err| {
            trc::StoreEvent::HttpStoreError
                .into_err()
                .reason(err)
                .ctx(trc::Key::Url, self.config.url.to_compact_string())
                .details("Failed to build request")
        })?;

        if !response.status().is_success() {
            trc::bail!(
                trc::StoreEvent::HttpStoreError
                    .into_err()
                    .ctx(trc::Key::Code, response.status().as_u16())
                    .ctx(trc::Key::Url, self.config.url.to_compact_string())
                    .ctx(trc::Key::Elapsed, time.elapsed())
                    .details("Failed to fetch HTTP list")
            );
        }

        let bytes = response
            .bytes_with_limit(self.config.max_size)
            .await
            .map_err(|err| {
                trc::StoreEvent::HttpStoreError
                    .into_err()
                    .reason(err)
                    .ctx(trc::Key::Url, self.config.url.to_compact_string())
                    .ctx(trc::Key::Elapsed, time.elapsed())
                    .details("Failed to fetch resource")
            })?
            .ok_or_else(|| {
                trc::StoreEvent::HttpStoreError
                    .into_err()
                    .ctx(trc::Key::Url, self.config.url.to_compact_string())
                    .ctx(trc::Key::Elapsed, time.elapsed())
                    .details("Resource is too large")
            })?;

        let reader: Box<dyn Read + Sync + Send> = if self.config.gzipped {
            Box::new(flate2::read::GzDecoder::new(&bytes[..]))
        } else {
            Box::new(&bytes[..])
        };

        let entries = self
            .config
            .parse_entries(BufReader::new(reader))
            .map_err(|err| {
                trc::StoreEvent::HttpStoreError
                    .into_err()
                    .reason(err)
                    .ctx(trc::Key::Url, self.config.url.to_compact_string())
                    .ctx(trc::Key::Elapsed, time.elapsed())
                    .details("Failed to read line")
            })?;

        trc::event!(
            Store(trc::StoreEvent::HttpStoreFetch),
            Url = self.config.url.to_compact_string(),
            Total = entries.len(),
            Elapsed = time.elapsed(),
        );

        Ok(entries)
    }
}

impl HttpStoreConfig {
    fn parse_entries(
        &self,
        mut reader: impl BufRead,
    ) -> io::Result<AHashMap<String, Value<'static>>> {
        let mut entries = AHashMap::new();
        let mut buf = Vec::new();
        let mut entry_key = String::new();
        let mut entry_value = String::new();

        for pos in 0usize.. {
            let line = match read_line(&mut reader, &mut buf, self.max_size)? {
                Line::Text(line) => line,
                Line::Oversize => continue,
                Line::Eof => break,
            };

            match &self.format {
                HttpStoreFormat::List => {
                    let line = line.trim();
                    if !line.is_empty() && line.len() <= self.max_entry_size {
                        entries.insert(lookup_key(line).into_owned(), Value::Integer(1));
                    }
                }
                HttpStoreFormat::Csv {
                    index_key,
                    index_value,
                    separator,
                    skip_first,
                } if pos > 0 || !*skip_first => {
                    let mut in_quote = false;
                    let mut col_num = 0;
                    let mut last_ch = ' ';
                    let mut oversize = false;

                    entry_key.clear();
                    entry_value.clear();

                    for ch in line.chars() {
                        match ch {
                            '"' if last_ch != '\\' => {
                                in_quote = !in_quote;
                            }
                            '\\' if last_ch != '\\' => (),
                            _ => {
                                if ch == *separator && !in_quote {
                                    if col_num == *index_key && index_value.is_none() {
                                        break;
                                    } else {
                                        col_num += 1;
                                    }
                                } else if col_num == *index_key {
                                    entry_key.push(ch);
                                    if entry_key.len() > self.max_entry_size {
                                        oversize = true;
                                        break;
                                    }
                                } else if index_value.is_some_and(|v| col_num == v) {
                                    entry_value.push(ch);
                                    if entry_value.len() > self.max_entry_size {
                                        oversize = true;
                                        break;
                                    }
                                }
                            }
                        }

                        last_ch = ch;
                    }

                    if !oversize && !entry_key.is_empty() {
                        let entry_value = if !entry_value.is_empty() {
                            Value::Text(Cow::Owned(String::from(entry_value.as_str())))
                        } else {
                            Value::Integer(1)
                        };
                        entries.insert(lookup_key(&entry_key).into_owned(), entry_value);
                    }
                }
                _ => (),
            }

            if entries.len() == self.max_entries {
                break;
            }
        }

        Ok(entries)
    }
}

enum Line<'x> {
    Text(&'x str),
    Oversize,
    Eof,
}

fn read_line<'x>(
    reader: &mut impl BufRead,
    buf: &'x mut Vec<u8>,
    max_len: usize,
) -> io::Result<Line<'x>> {
    buf.clear();
    let limit = u64::try_from(max_len).unwrap_or(u64::MAX).saturating_add(1);
    if reader.by_ref().take(limit).read_until(b'\n', buf)? == 0 {
        return Ok(Line::Eof);
    }
    let buf: &'x [u8] = buf;
    let line = match buf.strip_suffix(b"\n") {
        Some(line) => line.strip_suffix(b"\r").unwrap_or(line),
        None if buf.len() > max_len => {
            reader.skip_until(b'\n')?;
            return Ok(Line::Oversize);
        }
        None => buf,
    };
    str::from_utf8(line)
        .map(Line::Text)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn lookup_key(key: &str) -> Cow<'_, str> {
    let needs_lowercase = if key.is_ascii() {
        key.bytes().any(|b| b.is_ascii_uppercase())
    } else {
        key.chars().any(|ch| !ch.to_lowercase().eq([ch]))
    };
    if needs_lowercase {
        Cow::Owned(key.to_lowercase())
    } else {
        Cow::Borrowed(key)
    }
}

