/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    api::query::QueryResponseBuilder,
    registry::{
        mapping::{RegistryGetResponse, RegistryQueryResponse},
        query::RegistryQueryFilters,
    },
};
use chrono::DateTime;
use jmap_proto::types::state::State;
use registry::{
    jmap::IntoValue,
    schema::{enums::TracingLevel, prelude::Property, structs::Log},
    types::{EnumImpl, datetime::UTCDateTime},
};
use std::{
    borrow::Cow,
    fs::{self, File},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom},
    path::Path,
};
use store::{ahash::AHashMap, registry::RegistryFilterOp};
use tokio::sync::oneshot;
use trc::EventType;
use types::id::Id;

pub(crate) async fn log_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let Some(files) = get.server.core.metrics.log_files.clone() else {
        return Err(trc::JmapEvent::InvalidArguments
            .into_err()
            .details("No log tracers configured on the server"));
    };

    let ids = get.ids.take();

    if ids.as_ref().is_none_or(|ids| !ids.is_empty()) {
        // TODO: Use worker pool
        let limit = get.server.core.jmap.get_max_objects;
        let (tx, rx) = oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let _ = tx.send(read_log_entries(&files.path, &files.prefix, ids, limit));
        });

        rx.await
            .map_err(|err| {
                trc::EventType::Server(trc::ServerEvent::ThreadError)
                    .reason(err)
                    .caused_by(trc::location!())
            })?
            .map_err(|err| {
                trc::EventType::Telemetry(trc::TelemetryEvent::LogError)
                    .reason(err)
                    .details("Failed to read log files")
                    .caused_by(trc::location!())
            })?
            .into_iter()
            .for_each(|(id, log)| {
                get.insert(id, log.into_value());
            });
    }

    Ok(get)
}

pub(crate) async fn log_query(
    mut req: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    let Some(files) = req.server.core.metrics.log_files.clone() else {
        return Err(trc::JmapEvent::InvalidArguments
            .into_err()
            .details("No log tracers configured on the server"));
    };

    let mut filter = LogFilter::default();

    req.request
        .extract_filters(|property, op, value| match property {
            Property::Text => {
                if let serde_json::Value::String(text) = value {
                    filter.text = Some(text);
                    true
                } else {
                    false
                }
            }
            // inbuxa: the level picked and everything more severe, the way
            // `journalctl -p` reads a priority
            Property::Level => {
                if let Some(level) = value
                    .as_str()
                    .and_then(|v| TracingLevel::parse(&v.to_ascii_lowercase()))
                {
                    filter.level = Some(level as u8);
                    true
                } else {
                    false
                }
            }
            // inbuxa: a component (`smtp`, `store`) or a whole event id
            // (`smtp.connection-start`): the events whose id starts with it
            Property::Event => {
                if let Some(event) = value.as_str().map(|v| v.trim().to_ascii_lowercase())
                    && !event.is_empty()
                {
                    filter.event = Some(event);
                    true
                } else {
                    false
                }
            }
            Property::Timestamp => {
                if let Some(ts) = value
                    .as_str()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                {
                    let ts = ts.timestamp();
                    let (from, to) = match op {
                        RegistryFilterOp::Equal => (ts, ts),
                        RegistryFilterOp::GreaterThan => (ts.saturating_add(1), i64::MAX),
                        RegistryFilterOp::GreaterEqualThan => (ts, i64::MAX),
                        RegistryFilterOp::LowerThan => (i64::MIN, ts.saturating_sub(1)),
                        RegistryFilterOp::LowerEqualThan => (i64::MIN, ts),
                        RegistryFilterOp::TextMatch => return false,
                    };
                    filter.from = filter.from.max(from);
                    filter.to = filter.to.min(to);
                    true
                } else {
                    false
                }
            }
            _ => false,
        })?;

    let anchor = req.request.anchor.map(|id| id.id()).unwrap_or(0);
    let limit = std::cmp::min(
        req.request.limit.unwrap_or(usize::MAX),
        req.server.core.jmap.query_max_results,
    );

    let params = req
        .request
        .extract_parameters(req.server.core.jmap.query_max_results, Property::Id.into())?;

    if params.sort_by != Property::Id {
        return Err(trc::JmapEvent::UnsupportedSort
            .into_err()
            .details("Only sorting by 'id' is supported for logs"));
    }

    if req.request.position.unwrap_or(0) != 0 {
        return Err(trc::JmapEvent::InvalidArguments
            .into_err()
            .details("Pagination is only possible using anchors for logs"));
    }

    let (tx, rx) = oneshot::channel();

    tokio::task::spawn_blocking(move || {
        let _ = tx.send(read_log_offsets(
            &files.path,
            &files.prefix,
            &filter,
            anchor,
            limit,
        ));
    });

    // Build response
    let mut response = QueryResponseBuilder::new(
        req.server.core.jmap.query_max_results,
        req.server.core.jmap.query_max_results,
        State::Initial,
        &req.request,
    );

    response.response.ids = rx
        .await
        .map_err(|err| {
            trc::EventType::Server(trc::ServerEvent::ThreadError)
                .reason(err)
                .caused_by(trc::location!())
        })?
        .map_err(|err| {
            trc::EventType::Telemetry(trc::TelemetryEvent::LogError)
                .reason(err)
                .details("Failed to read log files")
                .caused_by(trc::location!())
        })?;
    response.anchor_found = true;

    // inbuxa: the total is only known when the first page reached the end
    // of the logs; counting them all would mean reading every file on every
    // page. Upstream answered the query cap (5000) as the total, so a
    // two-line log read "of 5000".
    response.response.total = (req.request.calculate_total.unwrap_or(false)
        && anchor == 0
        && response.response.ids.len() < limit)
        .then_some(response.response.ids.len());

    Ok(response)
}

/// inbuxa: what an x:Log/query asks for besides its anchor and limit.
#[derive(Debug)]
pub(crate) struct LogFilter {
    text: Option<String>,
    /// The least severe level wanted (0 = error ... 4 = trace).
    level: Option<u8>,
    /// An event id prefix.
    event: Option<String>,
    /// Seconds since the epoch, both inclusive.
    from: i64,
    to: i64,
}

impl Default for LogFilter {
    fn default() -> Self {
        LogFilter {
            text: None,
            level: None,
            event: None,
            from: i64::MIN,
            to: i64::MAX,
        }
    }
}

impl LogFilter {
    fn matches(&self, line: &str, header: &LogHeader<'_>) -> bool {
        (header.timestamp >= self.from && header.timestamp <= self.to)
            && self
                .level
                .is_none_or(|wanted| header.level.is_some_and(|level| level <= wanted))
            && self.event.as_deref().is_none_or(|prefix| {
                header.event.strip_prefix(prefix).is_some_and(|rest| {
                    rest.is_empty() || rest.starts_with('.') || prefix.ends_with('.')
                })
            })
            && self.text.as_deref().is_none_or(|text| line.contains(text))
    }
}

/// inbuxa: the start of a log line: `<RFC 3339> <LEVEL> <description> (<event id>)`.
struct LogHeader<'x> {
    timestamp: i64,
    level: Option<u8>,
    event: &'x str,
}

fn log_header(line: &str) -> Option<LogHeader<'_>> {
    // inbuxa (#456): a Log tracer writing JSON lines
    if line.starts_with('{') {
        let entry = serde_json::from_str::<JsonLogHead<'_>>(line).ok()?;
        return Some(LogHeader {
            timestamp: DateTime::parse_from_rfc3339(entry.timestamp)
                .ok()?
                .timestamp(),
            level: TracingLevel::parse(&entry.level.to_ascii_lowercase()).map(|l| l as u8),
            event: entry.event,
        });
    }
    if !line.as_bytes().first()?.is_ascii_digit() {
        return None;
    }
    let (timestamp, rest) = line.split_once(' ')?;
    let timestamp = DateTime::parse_from_rfc3339(timestamp).ok()?.timestamp();
    let (level, rest) = rest.trim_start().split_once(' ').unwrap_or((rest, ""));
    let level = TracingLevel::parse(&level.to_ascii_lowercase()).map(|level| level as u8);
    let event = rest
        .split_once(" (")
        .and_then(|(_, rest)| rest.split_once(')'))
        .map_or("", |(event, _)| event);
    Some(LogHeader {
        timestamp,
        level,
        event,
    })
}

/// inbuxa: the files the Log tracer writes in `dir`, newest first: one named
/// `prefix` (never rotated) or `prefix.` and the date and time it was
/// rotated at. Whatever else is there, links included, isn't the log and
/// isn't read.
fn tracer_log_files(dir: &Path, prefix: &str) -> io::Result<Vec<fs::DirEntry>> {
    let mut logs = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        // A DirEntry's type is the link's own, not its target's
        if entry.file_type()?.is_file()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| is_tracer_log_name(name, prefix))
        {
            logs.push(entry);
        }
    }
    logs.sort_by_key(|b| std::cmp::Reverse(b.file_name()));
    Ok(logs)
}

fn is_tracer_log_name(name: &str, prefix: &str) -> bool {
    !prefix.is_empty()
        && name.strip_prefix(prefix).is_some_and(|rest| {
            rest.is_empty()
                || rest.strip_prefix('.').is_some_and(|rotation| {
                    !rotation.is_empty()
                        && rotation
                            .bytes()
                            .all(|b| b.is_ascii_digit() || matches!(b, b'-' | b'T' | b':'))
                })
        })
}

fn read_log_offsets(
    path: impl AsRef<Path>,
    prefix: &str,
    filter: &LogFilter,
    anchor: u64,
    limit: usize,
) -> io::Result<Vec<Id>> {
    // inbuxa: a limit of 0 asks for no entries, not all of them
    if limit == 0 {
        return Ok(Vec::new());
    }

    let logs = tracer_log_files(path.as_ref(), prefix)?;

    let mut entries = Vec::with_capacity(limit);
    let mut file_number = 0u64;
    let mut found_anchor = anchor == 0;
    let file_anchor = anchor >> 48;

    'outer: for log in logs.into_iter() {
        if !found_anchor && file_anchor != file_number {
            file_number += 1;
            continue;
        }

        let file = File::open(log.path())?;
        let file_size = file.metadata()?.len();
        let mut rev_lines = RevLines::new(file);
        rev_lines.0.init_reader()?;

        let mut offset = file_size;

        for line in rev_lines {
            let line = line?;
            offset = offset.saturating_sub(line.len() as u64 + 1); // +1 for the newline character

            let plain = strip_ansi(&line);
            let Some(header) = log_header(&plain) else {
                continue;
            };

            let id = (file_number << 48) | offset;

            if !found_anchor {
                found_anchor = id == anchor;
                continue;
            }

            // inbuxa: files are read newest first, so the first entry older
            // than the range ends the search. A line or two out of order at
            // a rotation can be missed; reading every older file for them
            // would cost far more.
            if header.timestamp < filter.from {
                break 'outer;
            }

            if filter.matches(&plain, &header) {
                entries.push(Id::from(id));
                if entries.len() == limit {
                    break 'outer;
                }
            }
        }

        file_number += 1;
    }

    Ok(entries)
}

pub(crate) fn read_log_entries(
    path: impl AsRef<Path>,
    prefix: &str,
    ids: Option<Vec<Id>>,
    limit: usize,
) -> io::Result<Vec<(Id, Log)>> {
    let path = path.as_ref();
    let ids = if let Some(mut ids) = ids {
        ids.truncate(limit);
        ids
    } else {
        read_log_offsets(path, prefix, &LogFilter::default(), 0, limit)?
    };

    // Sorted by file name in reverse order
    let logs = tracer_log_files(path, prefix)?;

    let mut entries = Vec::with_capacity(ids.len());

    // Group files and offsets
    let mut offset_map = AHashMap::new();
    let total_ids = ids.len();
    for id in ids {
        let file_number = id.id() >> 48;
        let offset = id.id() & 0xFFFFFFFFFFFF;
        offset_map
            .entry(file_number)
            .or_insert_with(Vec::new)
            .push(offset);
    }

    let mut file_number = 0u64;
    let mut line = String::with_capacity(256);

    'outer: for log in logs.into_iter() {
        if let Some(offsets) = offset_map.get(&file_number) {
            let mut reader = BufReader::new(File::open(log.path())?);

            for offset in offsets {
                // seek to the offset and read the line
                reader.seek(SeekFrom::Start(*offset))?;
                line.clear();
                reader.read_line(&mut line)?;

                if let Some(log) = log_from_line(&line) {
                    entries.push((Id::from((file_number << 48) | *offset), log));

                    if entries.len() == total_ids {
                        break 'outer;
                    }
                }
            }
        }

        file_number += 1;
    }

    Ok(entries)
}

/// inbuxa (#456): the fields of a JSON log line that a query filters on.
#[derive(serde::Deserialize)]
struct JsonLogHead<'x> {
    #[serde(borrow)]
    timestamp: &'x str,
    #[serde(borrow)]
    level: &'x str,
    #[serde(borrow)]
    event: &'x str,
}

/// inbuxa (#456): a JSON log line, its `data` handed back as a JSON object
/// in `details`, so a reader gets the fields exactly as they were written.
#[derive(serde::Deserialize)]
struct JsonLogEntry<'x> {
    #[serde(borrow)]
    timestamp: &'x str,
    #[serde(borrow)]
    level: &'x str,
    #[serde(borrow)]
    event: &'x str,
    #[serde(default)]
    data: serde_json::Map<String, serde_json::Value>,
}

fn log_from_json_line(line: &str) -> Option<Log> {
    let entry = serde_json::from_str::<JsonLogEntry<'_>>(line.trim_end()).ok()?;
    Some(Log {
        timestamp: UTCDateTime::from_timestamp(
            DateTime::parse_from_rfc3339(entry.timestamp)
                .ok()?
                .timestamp(),
        ),
        level: TracingLevel::parse(&entry.level.to_ascii_lowercase()).unwrap_or(TracingLevel::Info),
        event: EventType::parse(entry.event)?,
        details: if entry.data.is_empty() {
            String::new()
        } else {
            serde_json::Value::Object(entry.data).to_string()
        },
    })
}

fn log_from_line(line: &str) -> Option<Log> {
    if line.starts_with('{') {
        return log_from_json_line(line);
    }
    let line = strip_ansi(line);
    let (timestamp, rest) = line.split_once(' ')?;
    let timestamp = DateTime::parse_from_rfc3339(timestamp).ok()?;
    let (level, rest) = rest.trim().split_once(' ')?;
    let (_, rest) = rest.trim().split_once(" (")?;
    let (event_id, details) = rest.split_once(")")?;

    Some(Log {
        timestamp: UTCDateTime::from_timestamp(timestamp.timestamp()),
        level: TracingLevel::parse(&level.to_ascii_lowercase()).unwrap_or(TracingLevel::Info),
        event: EventType::parse(event_id)?,
        details: details.trim().to_string(),
    })
}

fn strip_ansi(line: &str) -> Cow<'_, str> {
    if !line.contains('\x1b') {
        return Cow::Borrowed(line);
    }

    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('[') => {
                for c in chars.by_ref() {
                    if matches!(c as u32, 0x40..=0x7e) {
                        break;
                    }
                }
            }
            Some(']') => {
                while let Some(c) = chars.next() {
                    if c == '\x07' {
                        break;
                    }
                    if c == '\x1b' {
                        chars.next();
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    Cow::Owned(out)
}

/*
 * SPDX-FileCopyrightText: 2017 Michael Coyne <mjc@hey.com>
 *
 * SPDX-License-Identifier: MIT
 */

// Adapted from https://github.com/mjc-gh/rev_lines/blob/main/src/lib.rs

static DEFAULT_SIZE: usize = 4096;
static LF_BYTE: u8 = b'\n';

/// `RevLines` struct
pub struct RawRevLines<R> {
    reader: BufReader<R>,
    reader_cursor: u64,
    buffer: Vec<u8>,
    buffer_end: usize,
    read_len: usize,
}

impl<R: Seek + Read> RawRevLines<R> {
    /// Create a new `RawRevLines` struct from a Reader.
    /// Internal buffering for iteration will default to 4096 bytes at a time.
    pub fn new(reader: R) -> RawRevLines<R> {
        RawRevLines::with_capacity(DEFAULT_SIZE, reader)
    }

    /// Create a new `RawRevLines` struct from a Reader`.
    /// Internal buffering for iteration will use `cap` bytes at a time.
    pub fn with_capacity(cap: usize, reader: R) -> RawRevLines<R> {
        RawRevLines {
            reader: BufReader::new(reader),
            reader_cursor: u64::MAX,
            buffer: vec![0; cap],
            buffer_end: 0,
            read_len: 0,
        }
    }

    pub fn init_reader(&mut self) -> io::Result<()> {
        // Move cursor to the end of the file and store the cursor position
        self.reader_cursor = self.reader.seek(SeekFrom::End(0))?;
        // Next read will be the full buffer size or the remaining bytes in the file
        self.read_len = std::cmp::min(self.buffer.len(), self.reader_cursor as usize);
        // Move cursor just before the next bytes to read
        self.reader.seek_relative(-(self.read_len as i64))?;
        // Update the cursor position
        self.reader_cursor -= self.read_len as u64;

        self.read_to_buffer()?;

        // Handle any trailing new line characters for the reader
        // so the first next call does not return Some("")
        if self.buffer_end > 0
            && let Some(last_byte) = self.buffer.get(self.buffer_end - 1)
            && *last_byte == LF_BYTE
        {
            self.buffer_end -= 1;
        }

        Ok(())
    }

    fn read_to_buffer(&mut self) -> io::Result<()> {
        // Read the next bytes into the buffer, self.read_len was already prepared for that
        self.reader.read_exact(&mut self.buffer[0..self.read_len])?;
        // Specify which part of the buffer is valid
        self.buffer_end = self.read_len;

        // Determine what the next read length will be
        let next_read_len = std::cmp::min(self.buffer.len(), self.reader_cursor as usize);
        // Move the cursor just in front of the next read
        self.reader
            .seek_relative(-((self.read_len + next_read_len) as i64))?;
        // Update cursor position
        self.reader_cursor -= next_read_len as u64;

        // Store the next read length, it'll be used in the next call
        self.read_len = next_read_len;

        Ok(())
    }

    fn next_line(&mut self) -> io::Result<Option<Vec<u8>>> {
        // Reader cursor will only ever be u64::MAX if the reader has not been initialized
        // If by some chance the reader is initialized with a file of length u64::MAX this will still work,
        // as some read length value is subtracted from the cursor position right away
        if self.reader_cursor == u64::MAX {
            self.init_reader()?;
        }

        // For most sane scenarios, where size of the buffer is greater than the length of the line,
        // the result will only contain one and at most two elements, making the flattening trivial.
        // At the same time, instead of pushing one element at a time, it allows us to copy a subslice of the buffer,
        // which is very performant on modern architectures.
        let mut result: Vec<Vec<u8>> = Vec::new();

        'outer: loop {
            // Current buffer was read to completion, read new contents
            if self.buffer_end == 0 {
                // Read the of minimum between the desired
                // buffer size or remaining length of the reader
                self.read_to_buffer()?;
            }

            // If buffer_end is still 0, it means the reader is empty
            if self.buffer_end == 0 {
                if result.is_empty() {
                    return Ok(None);
                } else {
                    break;
                }
            }

            let buffer_length = self.buffer_end;

            for ch in self.buffer[..self.buffer_end].iter().rev() {
                self.buffer_end -= 1;
                // Found a new line character to break on
                if *ch == LF_BYTE {
                    result.push(self.buffer[self.buffer_end + 1..buffer_length].to_vec());
                    break 'outer;
                }
            }

            result.push(self.buffer[..buffer_length].to_vec());
        }

        Ok(Some(result.into_iter().rev().flatten().collect()))
    }
}

impl<R: Read + Seek> Iterator for RawRevLines<R> {
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<io::Result<Vec<u8>>> {
        self.next_line().transpose()
    }
}

pub struct RevLines<R>(RawRevLines<R>);

impl<R: Read + Seek> RevLines<R> {
    /// Create a new `RawRevLines` struct from a Reader.
    /// Internal buffering for iteration will default to 4096 bytes at a time.
    pub fn new(reader: R) -> RevLines<R> {
        RevLines(RawRevLines::new(reader))
    }

    /// Create a new `RawRevLines` struct from a Reader`.
    /// Internal buffering for iteration will use `cap` bytes at a time.
    pub fn with_capacity(cap: usize, reader: R) -> RevLines<R> {
        RevLines(RawRevLines::with_capacity(cap, reader))
    }
}

impl<R: Read + Seek> Iterator for RevLines<R> {
    type Item = Result<String, std::io::Error>;

    fn next(&mut self) -> Option<Result<String, std::io::Error>> {
        let line = match self.0.next_line().transpose()? {
            Ok(line) => line,
            Err(error) => return Some(Err(error)),
        };

        Some(
            String::from_utf8(line)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid UTF-8")),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{LogFilter, is_tracer_log_name, read_log_entries, read_log_offsets};

    #[test]
    fn limit_zero_reads_no_entries() {
        let dir = std::env::temp_dir().join(format!("inbuxa-log-limit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("server.log"),
            "2026-11-08T10:00:00Z INFO First (first)\n2026-11-08T10:00:01Z INFO Second (second)\n",
        )
        .unwrap();

        let none = read_log_offsets(&dir, "server.log", &LogFilter::default(), 0, 0).unwrap();
        let all = read_log_offsets(&dir, "server.log", &LogFilter::default(), 0, 10).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(none.is_empty(), "limit 0 returned {none:?}");
        assert_eq!(all.len(), 2);
    }

    // inbuxa (#229): level, component and time range filters
    #[test]
    fn filters_by_level_component_and_time() {
        let dir = std::env::temp_dir().join(format!("inbuxa-log-filter-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("inbuxa.log.2026-11-18"),
            concat!(
                "2026-11-18T10:00:00Z INFO SMTP connection started (smtp.connection-start) remoteIp = 192.0.2.1\n",
                "2026-11-18T10:00:01Z WARN Store error (store.data-corruption) details = \"x\"\n",
                "2026-11-18T10:00:02Z ERROR SMTPS thing (smtps.error) reason = \"y\"\n",
                "2026-11-18T10:00:03Z \u{1b}[1;34mDEBUG\u{1b}[0m SMTP rcpt (smtp.rcpt-to) to = \"a@example.org\"\n",
            ),
        )
        .unwrap();
        let count = |filter: LogFilter| {
            read_log_offsets(&dir, "inbuxa.log", &filter, 0, 10)
                .unwrap()
                .len()
        };

        let at_least_warn = count(LogFilter {
            level: Some(1),
            ..Default::default()
        });
        let smtp = count(LogFilter {
            event: Some("smtp".into()),
            ..Default::default()
        });
        let exact = count(LogFilter {
            event: Some("smtp.rcpt-to".into()),
            ..Default::default()
        });
        let window = count(LogFilter {
            from: 1_794_996_001,
            to: 1_794_996_002,
            ..Default::default()
        });
        let after = count(LogFilter {
            from: 1_794_996_002,
            ..Default::default()
        });
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(at_least_warn, 2, "warn and error");
        assert_eq!(smtp, 2, "smtp.* but not smtps.*");
        assert_eq!(exact, 1);
        assert_eq!(window, 2);
        assert_eq!(after, 2);
    }

    // inbuxa (#456): files written as JSON lines are queried and read like
    // text ones, and a mix of both (a tracer switched over) reads in order
    #[test]
    fn reads_json_lines() {
        let dir = std::env::temp_dir().join(format!("inbuxa-log-json-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("inbuxa.log.2026-11-18"),
            concat!(
                "2026-11-18T10:00:00Z INFO SMTP connection started (smtp.connection-start) remoteIp = 192.0.2.1\n",
                r#"{"timestamp":"2026-11-18T10:00:01Z","level":"warn","event":"store.data-corruption","description":"Data corruption","data":{"details":"a \"quoted\" word, with a comma"}}"#,
                "\n",
                r#"{"timestamp":"2026-11-18T10:00:02Z","level":"error","event":"imap.connection-end","description":"x","data":{}}"#,
                "\n",
                r#"{"timestamp":"2026-11-18T10:00:03Z","level":"debug","event":"smtp.rcpt-to","description":"y","data":{"to":["a@example.org"],"size":12}}"#,
                "\n",
            ),
        )
        .unwrap();
        let ids = |filter: LogFilter| read_log_offsets(&dir, "inbuxa.log", &filter, 0, 10).unwrap();

        let all = ids(LogFilter::default());
        let at_least_warn = ids(LogFilter {
            level: Some(1),
            ..Default::default()
        });
        let smtp = ids(LogFilter {
            event: Some("smtp".into()),
            ..Default::default()
        });
        let window = ids(LogFilter {
            from: 1_794_996_001,
            to: 1_794_996_002,
            ..Default::default()
        });
        let text = ids(LogFilter {
            text: Some("comma".into()),
            ..Default::default()
        });
        let entries = read_log_entries(&dir, "inbuxa.log", Some(all.clone()), 10).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(all.len(), 4);
        assert_eq!(at_least_warn.len(), 2, "warn and error");
        assert_eq!(smtp.len(), 2, "smtp.* only");
        assert_eq!(window.len(), 2);
        assert_eq!(text.len(), 1);

        // Newest first
        let events = entries
            .iter()
            .map(|(_, log)| log.event.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            events,
            [
                "smtp.rcpt-to",
                "imap.connection-end",
                "store.data-corruption",
                "smtp.connection-start"
            ]
        );
        let details = |i: usize| entries[i].1.details.as_str();
        let rcpt: serde_json::Value = serde_json::from_str(details(0)).unwrap();
        assert_eq!(
            rcpt,
            serde_json::json!({"to": ["a@example.org"], "size": 12})
        );
        assert_eq!(details(1), "", "no fields, no details");
        let corruption: serde_json::Value = serde_json::from_str(details(2)).unwrap();
        assert_eq!(corruption["details"], "a \"quoted\" word, with a comma");
        assert_eq!(details(3), "remoteIp = 192.0.2.1");
        assert_eq!(entries[2].1.level as u8, 1);
    }

    // inbuxa (#456): what the Log tracer writes as JSON reads back exactly
    #[test]
    fn json_tracer_output_reads_back() {
        use trc::{Event, EventDetails, EventType, Key, Level, SmtpEvent, Value};

        let event = Event {
            inner: EventDetails {
                typ: EventType::Smtp(SmtpEvent::RcptTo),
                timestamp: 1_794_996_000,
                level: Level::Debug,
                span: Some(std::sync::Arc::new(Event {
                    inner: EventDetails {
                        typ: EventType::Smtp(SmtpEvent::ConnectionStart),
                        timestamp: 1_794_995_999,
                        level: Level::Info,
                        span: None,
                    },
                    keys: vec![(Key::RemoteIp, Value::String("192.0.2.1".into()))],
                })),
            },
            keys: vec![(Key::To, Value::String("a \"b\", c@example.org".into()))],
        };
        let mut line = serde_json::to_string(&trc::serializers::json::JsonLogLine(&event)).unwrap();
        line.push('\n');

        let dir = std::env::temp_dir().join(format!("inbuxa-log-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("inbuxa.log"), &line).unwrap();
        let ids = read_log_offsets(
            &dir,
            "inbuxa.log",
            &LogFilter {
                level: Some(3),
                event: Some("smtp.rcpt-to".into()),
                ..Default::default()
            },
            0,
            10,
        )
        .unwrap();
        let entries = read_log_entries(&dir, "inbuxa.log", Some(ids), 10).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(entries.len(), 1);
        let log = &entries[0].1;
        assert_eq!(log.event, EventType::Smtp(SmtpEvent::RcptTo));
        assert_eq!(log.level as u8, 3);
        assert_eq!(log.timestamp.timestamp(), 1_794_996_000);
        let data: serde_json::Value = serde_json::from_str(&log.details).unwrap();
        assert_eq!(
            data,
            serde_json::json!({"to": "a \"b\", c@example.org", "remoteIp": "192.0.2.1"})
        );
    }

    // inbuxa: only the names the Log tracer gives its files are read
    #[test]
    fn reads_only_the_tracers_files() {
        for (name, expected) in [
            ("inbuxa", true),
            ("inbuxa.2026-11-23", true),
            ("inbuxa.2026-11-23T10", true),
            ("inbuxa.2026-11-23T10:05", true),
            ("inbuxa.", false),
            ("inbuxa.2026-11-23.gz", false),
            ("inbuxa.secret", false),
            ("inbuxa2026", false),
            ("other.log", false),
            ("..", false),
        ] {
            assert_eq!(is_tracer_log_name(name, "inbuxa"), expected, "{name}");
        }
        assert!(!is_tracer_log_name("anything", ""));

        let dir = std::env::temp_dir().join(format!("inbuxa-log-own-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let line = |marker: &str| {
            format!(
                "2026-11-23T10:00:00Z INFO Licensing (server.licensing) details = \"{marker}\"\n"
            )
        };
        std::fs::write(dir.join("inbuxa.2026-11-23"), line("own")).unwrap();
        std::fs::write(dir.join("other.log"), line("foreign")).unwrap();
        let outside = dir.with_extension("outside");
        std::fs::write(&outside, line("linked")).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("inbuxa.2026-11-22")).unwrap();
        let entries = read_log_entries(&dir, "inbuxa", None, 10).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_file(&outside).unwrap();

        assert_eq!(entries.len(), 1, "{entries:?}");
        assert!(entries[0].1.details.contains("own"), "{entries:?}");
    }
}
