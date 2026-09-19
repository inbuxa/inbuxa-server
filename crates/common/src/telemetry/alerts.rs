/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Alerts (monitoring spec MON-25 to MON-30). Each enabled `x:Alert` is read
//! from the registry at evaluation, so a change needs no reload (MON-3), and
//! fires when its condition goes from false to true (MON-26).

use crate::{
    Server,
    expr::{functions::EmptyResolver, if_block::BootstrapExprExt},
};
use ahash::AHashSet;
use mail_builder::{
    MessageBuilder,
    headers::{HeaderType, address::Address},
};
use registry::{
    schema::{
        prelude::{ExpressionContext, ObjectType},
        structs::{Alert, AlertEmail, AlertEvent, Expression, ExpressionMatch},
    },
    types::{id::ObjectId, list::List},
};
use std::sync::Mutex;
use store::registry::{RegistryQuery, bootstrap::Bootstrap};
use trc::{Collector, MetricType, TelemetryEvent};
use types::id::Id;

/// An alert email, ready to queue.
#[derive(Debug, Clone)]
pub struct AlertMessage {
    pub from: String,
    pub to: Vec<String>,
    pub body: Vec<u8>,
}

/// The alerts whose condition held at the last evaluation (MON-26). In
/// memory, so a restart while a condition holds fires once more.
static FIRING: Mutex<Option<AHashSet<u64>>> = Mutex::new(None);

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The metric an underscore name stands for (`queue_count`), MON-25.
fn underscore_metric(name: &str) -> Option<MetricType> {
    static NAMES: std::sync::OnceLock<ahash::AHashMap<String, MetricType>> =
        std::sync::OnceLock::new();
    if !name.contains('_') {
        return None;
    }
    NAMES
        .get_or_init(|| {
            (0..=u16::MAX)
                .filter_map(MetricType::from_id)
                .map(|metric| (metric.as_str().replace(['.', '-'], "_"), metric))
                .collect()
        })
        .get(name)
        .copied()
}

/// Rewrites bare underscore metric names into `metric('dotted.name')`,
/// leaving quoted text and function names alone (MON-25).
pub fn rewrite(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let chars = text.chars().collect::<Vec<_>>();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' || c == '\'' {
            let quote = c;
            out.push(c);
            i += 1;
            while i < chars.len() {
                out.push(chars[i]);
                if chars[i] == quote {
                    break;
                }
                i += 1;
            }
            i += 1;
        } else if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && is_ident_char(chars[i]) {
                i += 1;
            }
            let word = chars[start..i].iter().collect::<String>();
            let is_call = chars[i..].iter().find(|c| !c.is_whitespace()) == Some(&'(');
            match underscore_metric(&word) {
                Some(metric) if !is_call => {
                    out.push_str(&format!("metric('{}')", metric.as_str()));
                }
                _ => out.push_str(&word),
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// An alert condition with underscore names rewritten.
pub fn rewrite_condition(condition: &Expression) -> Expression {
    Expression {
        match_: List::from_iter(condition.match_.iter().map(|m| ExpressionMatch {
            if_: rewrite(&m.if_),
            then: rewrite(&m.then),
        })),
        else_: rewrite(&condition.else_),
    }
}

/// `%{metric.name}%` replaced by the metric's value: whole numbers without
/// decimals, others with at most two (MON-27). Unknown names stay.
pub fn render(template: &str) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("%{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}%") {
            Some(end) => {
                let name = &after[..end];
                match MetricType::parse(name) {
                    Some(metric) => {
                        let value = Collector::read_metric(metric);
                        if value.fract() == 0.0 {
                            out.push_str(&format!("{}", value as i64));
                        } else {
                            let text = format!("{value:.2}");
                            out.push_str(text.trim_end_matches('0').trim_end_matches('.'));
                        }
                    }
                    None => out.push_str(&rest[start..start + 2 + end + 2]),
                }
                rest = &after[end + 2..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

fn build_email(email: &registry::schema::structs::AlertEmailProperties) -> AlertMessage {
    let from = match &email.from_name {
        Some(name) => Address::new_address(Some(name.clone()), email.from_address.clone()),
        None => Address::new_address(None::<String>, email.from_address.clone()),
    };
    let to = email.to.iter().cloned().collect::<Vec<_>>();
    let body = MessageBuilder::new()
        .from(from)
        .to(to
            .iter()
            .map(|addr| Address::new_address(None::<String>, addr.clone()))
            .collect::<Vec<_>>())
        .subject(render(&email.subject))
        .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
        .text_body(render(&email.body))
        .write_to_vec()
        .unwrap_or_default();
    AlertMessage {
        from: email.from_address.clone(),
        to,
        body,
    }
}

impl Server {
    /// Evaluates every enabled alert once (MON-25, MON-26), emits the event
    /// of each that fires (MON-28), and returns the emails to queue
    /// (MON-29). A failing alert is logged and skipped (MON-37).
    pub async fn process_alerts(&self) -> trc::Result<Vec<AlertMessage>> {
        let registry = self.registry();
        let ids = registry
            .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Alert))
            .await?;
        let mut messages = Vec::new();
        let mut holding = AHashSet::new();
        for id in ids {
            let Some(alert) = registry.object::<Alert>(id).await? else {
                continue;
            };
            if !alert.enable {
                continue;
            }
            let condition = rewrite_condition(&alert.condition);
            let mut bp = Bootstrap::new_uninitialized(registry.clone());
            let if_block = bp.compile_expr(
                ObjectId::new(ObjectType::Alert, id),
                &ExpressionContext {
                    expr: &condition,
                    ..alert.ctx_condition()
                },
            );
            if !bp.errors.is_empty() || if_block.is_empty() {
                trc::event!(
                    Registry(trc::RegistryEvent::BuildWarning),
                    Id = id.id(),
                    Details = "The alert's condition can't be evaluated",
                );
                continue;
            }
            let holds = self
                .eval_if::<bool, _>(&if_block, &EmptyResolver, 0)
                .await
                .unwrap_or(false);
            if !holds {
                continue;
            }
            holding.insert(id.id());
            let was_firing = FIRING
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|firing| firing.contains(&id.id()));
            if was_firing {
                continue;
            }

            if let AlertEvent::Enabled(event) = &alert.event_alert {
                trc::event!(
                    Telemetry(TelemetryEvent::AlertEvent),
                    Id = id.id(),
                    Details = render(event.event_message.as_deref().unwrap_or("Alert triggered")),
                );
            }
            if let AlertEmail::Enabled(email) = &alert.email_alert {
                messages.push(build_email(email));
            }
        }
        *FIRING.lock().unwrap() = Some(holding);
        Ok(messages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_underscore_names() {
        assert_eq!(rewrite("domain_count > 1"), "metric('domain.count') > 1");
        assert_eq!(
            rewrite("metric('queue.count') > 5 && queue_count < 9"),
            "metric('queue.count') > 5 && metric('queue.count') < 9"
        );
        assert_eq!(rewrite("'domain_count' == x"), "'domain_count' == x");
        assert_eq!(rewrite("unknown_thing > 1"), "unknown_thing > 1");
    }

    #[test]
    fn renders_placeholders() {
        assert_eq!(render("no placeholders"), "no placeholders");
        assert_eq!(render("%{no.such-metric}% left"), "%{no.such-metric}% left");
    }
}
