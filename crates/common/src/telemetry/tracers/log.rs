/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use std::{path::PathBuf, time::SystemTime};

use crate::config::telemetry::{LogTracer, RotationStrategy};

use mail_parser::DateTime;
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncWriteExt, BufWriter},
};
use trc::{
    Event, EventDetails, TelemetryEvent,
    ipc::subscriber::SubscriberBuilder,
    serializers::{json::JsonLogLine, text::FmtWriter},
};

// inbuxa (#456): a Log tracer writes text, as upstream, or one JSON object
// per line.
enum LogWriter {
    Text(FmtWriter<BufWriter<File>>),
    Json(BufWriter<File>, Vec<u8>),
}

impl LogWriter {
    fn new(writer: BufWriter<File>, settings: &LogTracer) -> Self {
        if settings.json {
            LogWriter::Json(writer, Vec::with_capacity(512))
        } else {
            LogWriter::Text(
                FmtWriter::new(writer)
                    .with_ansi(settings.ansi)
                    .with_multiline(settings.multiline),
            )
        }
    }

    async fn write(&mut self, event: &Event<EventDetails>) -> std::io::Result<()> {
        match self {
            LogWriter::Text(writer) => writer.write(event).await,
            LogWriter::Json(writer, line) => {
                line.clear();
                json_log_line(event, line)?;
                writer.write_all(line).await
            }
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            LogWriter::Text(writer) => writer.flush().await,
            LogWriter::Json(writer, _) => writer.flush().await,
        }
    }

    fn update_writer(&mut self, new: BufWriter<File>) {
        match self {
            LogWriter::Text(writer) => writer.update_writer(new),
            LogWriter::Json(writer, _) => *writer = new,
        }
    }
}

/// inbuxa (#456): an event as one line of JSON, newline included.
pub(crate) fn json_log_line(event: &Event<EventDetails>, out: &mut Vec<u8>) -> std::io::Result<()> {
    serde_json::to_writer(&mut *out, &JsonLogLine(event)).map_err(std::io::Error::other)?;
    out.push(b'\n');
    Ok(())
}

// inbuxa: when a Log tracer is started over on the same files (its rotation
// or format changed), the new one waits for the old one to write what it
// has queued, so their lines don't interleave. Keyed by path and prefix;
// each entry is the last tracer's "done" signal, sent when it ends.
type LogFileOwners = ahash::AHashMap<(String, String), tokio::sync::oneshot::Receiver<()>>;
static LOG_FILE_OWNERS: parking_lot::Mutex<Option<LogFileOwners>> = parking_lot::Mutex::new(None);

pub(crate) fn spawn_log_tracer(builder: SubscriberBuilder, settings: LogTracer) {
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let previous = LOG_FILE_OWNERS
        .lock()
        .get_or_insert_with(Default::default)
        .insert((settings.path.clone(), settings.prefix.clone()), done_rx);
    let (_, mut rx) = builder.register();
    tokio::spawn(async move {
        // Dropped when this tracer ends, however it ends
        let _done = done_tx;
        if let Some(previous) = previous {
            let _ = previous.await;
        }

        if let Some(writer) = settings.build_writer().await {
            let mut buf = LogWriter::new(writer, &settings);
            let mut roatation_timestamp = settings.next_rotation();

            while let Some(events) = rx.recv().await {
                for event in events {
                    // Check if we need to rotate the log file
                    if roatation_timestamp != 0 && event.inner.timestamp > roatation_timestamp {
                        if let Err(err) = buf.flush().await {
                            trc::event!(
                                Telemetry(TelemetryEvent::LogError),
                                Reason = err.to_string(),
                                Details = "Failed to flush log buffer"
                            );
                        }

                        if let Some(writer) = settings.build_writer().await {
                            buf.update_writer(writer);
                            roatation_timestamp = settings.next_rotation();
                        } else {
                            return;
                        };
                    }

                    if let Err(err) = buf.write(&event).await {
                        trc::event!(
                            Telemetry(TelemetryEvent::LogError),
                            Reason = err.to_string(),
                            Details = "Failed to write event to log"
                        );
                        return;
                    }
                }

                if let Err(err) = buf.flush().await {
                    trc::event!(
                        Telemetry(TelemetryEvent::LogError),
                        Reason = err.to_string(),
                        Details = "Failed to flush log buffer"
                    );
                }
            }
        }
    });
}

impl LogTracer {
    pub async fn build_writer(&self) -> Option<BufWriter<File>> {
        let now = DateTime::from_timestamp(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()) as i64,
        );
        let file_name = match self.rotate {
            RotationStrategy::Daily => {
                format!(
                    "{}.{:04}-{:02}-{:02}",
                    self.prefix, now.year, now.month, now.day
                )
            }
            RotationStrategy::Hourly => {
                format!(
                    "{}.{:04}-{:02}-{:02}T{:02}",
                    self.prefix, now.year, now.month, now.day, now.hour
                )
            }
            RotationStrategy::Minutely => {
                format!(
                    "{}.{:04}-{:02}-{:02}T{:02}:{:02}",
                    self.prefix, now.year, now.month, now.day, now.hour, now.minute
                )
            }
            RotationStrategy::Never => self.prefix.clone(),
        };
        let path = PathBuf::from(&self.path).join(file_name);

        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
        {
            Ok(writer) => Some(BufWriter::new(writer)),
            Err(err) => {
                trc::event!(
                    Telemetry(TelemetryEvent::LogError),
                    Details = "Failed to create log file",
                    Path = path.to_string_lossy().into_owned(),
                    Reason = err.to_string(),
                );
                None
            }
        }
    }

    pub fn next_rotation(&self) -> u64 {
        let mut now = DateTime::from_timestamp(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()) as i64,
        );

        now.second = 0;

        match self.rotate {
            RotationStrategy::Daily => {
                now.hour = 0;
                now.minute = 0;
                now.to_timestamp() as u64 + 86400
            }
            RotationStrategy::Hourly => {
                now.minute = 0;
                now.to_timestamp() as u64 + 3600
            }
            RotationStrategy::Minutely => now.to_timestamp() as u64 + 60,
            RotationStrategy::Never => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::json_log_line;
    use trc::{Event, EventDetails, EventType, Key, Level, SmtpEvent, Value};

    // inbuxa (#456): a JSON line is one object with typed fields
    #[test]
    fn json_line_is_one_typed_object() {
        let event = Event {
            inner: EventDetails {
                typ: EventType::Smtp(SmtpEvent::ConnectionStart),
                timestamp: 1_794_996_000,
                level: Level::Info,
                span: None,
            },
            keys: vec![
                (Key::RemoteIp, Value::String("192.0.2.1".into())),
                (Key::RemotePort, Value::UInt(25)),
                (
                    Key::Details,
                    Value::String("a \"quoted\" word\nand a line".into()),
                ),
                (
                    Key::Contents,
                    Value::Array(vec![Value::Bool(true), Value::Int(-1)]),
                ),
            ],
        };
        let mut out = Vec::new();
        json_log_line(&event, &mut out).unwrap();

        let text = String::from_utf8(out).unwrap();
        assert!(text.ends_with('\n'));
        assert_eq!(text.matches('\n').count(), 1, "one line: {text}");
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["timestamp"], "2026-11-18T10:00:00Z");
        assert_eq!(json["level"], "info");
        assert_eq!(json["event"], "smtp.connection-start");
        assert!(json["description"].as_str().is_some_and(|d| !d.is_empty()));
        assert_eq!(json["data"]["remoteIp"], "192.0.2.1");
        assert_eq!(json["data"]["remotePort"], 25);
        assert_eq!(json["data"]["details"], "a \"quoted\" word\nand a line");
        assert_eq!(json["data"]["contents"], serde_json::json!([true, -1]));
    }
}
