/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Calling the operator's model (AI spam classification spec, AI-5 to AI-11,
//! AI-21 to AI-25). The rules live in `inbuxa_features::ai`; this makes the
//! HTTP request. The wire types are the OpenAI-compatible chat completions
//! shapes local model servers speak.

use crate::Server;
use inbuxa_features::ai::{
    gate::{Gate, Refused, Transition},
    limits::{self, AiLimits},
    locality,
    request::{self, Kind, MAX_RESPONSE_BYTES},
};
use registry::schema::{
    enums::AiOpenAiProfile,
    prelude::ObjectType,
    structs::{AiModel, SecretKeyOptional, SpamAi},
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use store::registry::RegistryQuery;
use trc::AiEvent;
use types::id::Id;
use utils::map::vec_map::VecMap;

/// A chat completions request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub stream: bool,
}

/// One chat message.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

/// A chat completions response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChatCompletionResponse {
    pub created: i64,
    pub object: String,
    pub id: String,
    pub model: String,
    pub choices: Vec<ChatCompletionChoice>,
}

/// One choice in a response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChatCompletionChoice {
    pub index: u32,
    pub finish_reason: String,
    pub message: Message,
}

/// Why a call produced no answer. Every one leaves mail flowing (AI-9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    Refused(Refused),
    Timeout,
    Http(String),
    Status(u16),
    BadAnswer,
    Unsupported(&'static str),
}

/// One call to make.
pub struct Call<'x> {
    pub model_id: Id,
    pub model: &'x AiModel,
    /// Set for an account's own script (AI-24, AI-25).
    pub account_id: Option<u32>,
    pub system: Option<&'x str>,
    pub user: &'x str,
    /// `None` leaves it to the provider.
    pub temperature: Option<f64>,
    pub max_tokens: u32,
    pub timeout: Duration,
    /// Set for "Explain this" (ai-explain spec, EX-10, EX-14, EX-15).
    pub explain: Option<Explain<'x>>,
    /// inbuxa: EX-23, set to stream: each piece of the answer is sent here as
    /// the model writes it. The call still returns the whole answer.
    pub stream: Option<tokio::sync::mpsc::UnboundedSender<String>>,
}

/// What an explanation call does differently: it leaves a slot for mail,
/// counts against the administrator's explanations, and is logged without
/// its answer.
pub struct Explain<'x> {
    pub calls_per_hour: u32,
    /// The subject's type, the only thing about it that is logged.
    pub subject: &'x str,
}

/// inbuxa: 1.0 split `x:AiModel` into one variant per provider. These are
/// the settings every variant has, and where a call goes.
pub trait AiModelExt {
    fn name(&self) -> &str;
    fn model(&self) -> &str;
    fn api_key(&self) -> &SecretKeyOptional;
    fn http_headers(&self) -> &VecMap<String, String>;
    fn allow_invalid_certs(&self) -> bool;
    fn timeout(&self) -> Duration;
    /// The model's own temperature; `None` leaves it to the provider.
    fn temperature(&self) -> Option<f64>;
    /// The configured base URL, or the provider's default.
    fn base_url(&self) -> &str;
    /// The chat completions URL, or why this build can't call the provider.
    fn endpoint(&self) -> Result<String, Failure>;
}

macro_rules! each_model {
    ($model:expr, $m:ident => $e:expr) => {
        match $model {
            AiModel::OpenAi($m) => $e,
            AiModel::Anthropic($m) => $e,
            AiModel::Gemini($m) => $e,
            AiModel::Ollama($m) => $e,
            AiModel::TypeSafe($m) => $e,
        }
    };
}

/// A base URL with `path` added, unless it already names an endpoint (0.16
/// models stored the full chat completions URL).
fn join_endpoint(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    if base.ends_with("/completions") {
        base.to_string()
    } else {
        format!("{base}{path}")
    }
}

impl AiModelExt for AiModel {
    fn name(&self) -> &str {
        each_model!(self, m => &m.name)
    }

    fn model(&self) -> &str {
        each_model!(self, m => &m.model)
    }

    fn api_key(&self) -> &SecretKeyOptional {
        each_model!(self, m => &m.api_key)
    }

    fn http_headers(&self) -> &VecMap<String, String> {
        each_model!(self, m => &m.http_headers)
    }

    fn allow_invalid_certs(&self) -> bool {
        each_model!(self, m => m.allow_invalid_certs)
    }

    fn timeout(&self) -> Duration {
        each_model!(self, m => m.timeout.into_inner())
    }

    fn temperature(&self) -> Option<f64> {
        match self {
            AiModel::OpenAi(m) => m.temperature,
            AiModel::Anthropic(m) => m.temperature,
            AiModel::Gemini(m) => m.temperature,
            AiModel::Ollama(m) => m.temperature,
            AiModel::TypeSafe(_) => None,
        }
        .map(|t| t.into_inner())
    }

    fn base_url(&self) -> &str {
        let default = match self {
            AiModel::OpenAi(_) => "https://api.openai.com/v1",
            AiModel::Anthropic(_) => "https://api.anthropic.com",
            AiModel::Gemini(_) => "https://generativelanguage.googleapis.com",
            AiModel::Ollama(_) => "http://localhost:11434",
            AiModel::TypeSafe(_) => "",
        };
        each_model!(self, m => m.url.as_deref())
            .filter(|url| !url.trim().is_empty())
            .unwrap_or(default)
    }

    fn endpoint(&self) -> Result<String, Failure> {
        match self {
            AiModel::OpenAi(_) => Ok(join_endpoint(self.base_url(), "/chat/completions")),
            AiModel::Ollama(_) => {
                let base = self.base_url().trim_end_matches('/');
                Ok(if base.ends_with("/v1") {
                    join_endpoint(base, "/chat/completions")
                } else {
                    join_endpoint(base, "/v1/chat/completions")
                })
            }
            // inbuxa: our client speaks the OpenAI-compatible chat wire;
            // these providers' own APIs are a follow-up
            AiModel::Anthropic(_) | AiModel::Gemini(_) | AiModel::TypeSafe(_) => Err(
                Failure::Unsupported("This provider isn't supported yet; use an OpenAI-compatible or Ollama model"),
            ),
        }
    }
}

/// inbuxa: EX-23, reads a streamed answer, forwarding each piece. A listener
/// that has gone away doesn't stop the read: the answer is still wanted, to
/// be remembered (EX-24).
async fn read_stream(
    kind: Kind,
    response: &mut reqwest::Response,
    stream: &tokio::sync::mpsc::UnboundedSender<String>,
) -> Result<String, Failure> {
    let mut pending = Vec::new();
    let mut answer = String::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| Failure::Http(err.without_url().to_string()))?
    {
        pending.extend_from_slice(&chunk);
        while let Some(at) = pending.iter().position(|b| *b == b'\n') {
            let line = pending.drain(..=at).collect::<Vec<_>>();
            match request::stream_line(kind, &String::from_utf8_lossy(&line)) {
                request::StreamLine::Delta(text) => {
                    answer.push_str(&text);
                    if answer.len() > MAX_RESPONSE_BYTES {
                        return Err(Failure::BadAnswer);
                    }
                    let _ = stream.send(text);
                }
                request::StreamLine::Done => return finished(answer),
                request::StreamLine::Ignore => {}
            }
        }
        if pending.len() > MAX_RESPONSE_BYTES {
            return Err(Failure::BadAnswer);
        }
    }
    finished(answer)
}

fn finished(answer: String) -> Result<String, Failure> {
    let answer = answer.trim();
    if answer.is_empty() {
        Err(Failure::BadAnswer)
    } else {
        Ok(answer.to_string())
    }
}

impl Server {
    /// The fork's limits, as stored now.
    pub async fn ai_limits(&self) -> AiLimits {
        limits::get(&self.core.storage.data)
            .await
            .unwrap_or_default()
    }

    /// A model by its id.
    pub async fn ai_model_by_id(&self, id: Id) -> Option<AiModel> {
        self.registry().object::<AiModel>(id).await.ok().flatten()
    }

    /// A model by name, or failing that by id (AI-20).
    pub async fn ai_model_by_name(&self, name: &str) -> Option<(Id, AiModel)> {
        let ids = self
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(ObjectType::AiModel))
            .await
            .ok()?;
        let mut by_id = None;
        for id in ids {
            if let Some(model) = self.ai_model_by_id(id).await {
                if model.name() == name {
                    return Some((id, model));
                }
                if id.to_string() == name {
                    by_id = Some((id, model));
                }
            }
        }
        by_id
    }

    /// The model "Explain this" asks (ai-explain spec, EX-3): the one chosen
    /// for explanations, else the spam classifier's, else the only model
    /// there is. `None` when explanations are off or no model resolves.
    pub async fn ai_explain_model(&self, limits: &AiLimits) -> Option<(Id, AiModel)> {
        if !limits.explain_enabled {
            return None;
        }
        if let Some(id) = limits.explain_model_id {
            let id = Id::from(id);
            return self.ai_model_by_id(id).await.map(|model| (id, model));
        }
        // inbuxa: 1.0's spam classifier has tiers of models: its first
        if let Ok(Some(SpamAi::Enable(settings))) =
            self.registry().object::<SpamAi>(Id::singleton()).await
            && let Some(tier) = settings.tiers.iter().next()
            && let Some(model) = self.ai_model_by_id(tier.model_id).await
        {
            return Some((tier.model_id, model));
        }
        let ids = self
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(ObjectType::AiModel))
            .await
            .ok()?;
        match ids.as_slice() {
            [id] => self.ai_model_by_id(*id).await.map(|model| (*id, model)),
            _ => None,
        }
    }

    /// Makes one call. The answer, or why there is none; either way the
    /// outcome is logged, with no message content and no secret (AI-5).
    pub async fn ai_call(&self, call: Call<'_>) -> Result<String, Failure> {
        let limits = self.ai_limits().await;
        let gate = Gate::global();
        let attempt = match (&call.explain, call.account_id) {
            (Some(explain), Some(account_id)) => gate.try_start_explain(
                call.model_id.id(),
                account_id,
                limits.gate(),
                explain.calls_per_hour,
            ),
            _ => gate.try_start(call.model_id.id(), call.account_id, limits.gate()),
        };
        let permit = match attempt {
            Ok(permit) => permit,
            Err(refused) => {
                trc::event!(
                    Ai(AiEvent::ApiError),
                    Details = call.model.name().to_string(),
                    AccountId = call.account_id,
                    Reason = format!("{refused:?}"),
                );
                return Err(Failure::Refused(refused));
            }
        };
        let started = Instant::now();
        let result = tokio::time::timeout(call.timeout, self.ai_request(&call)).await;
        let result = match result {
            Ok(result) => result,
            Err(_) => Err(Failure::Timeout),
        };
        let transition = permit.finish(result.is_ok(), limits.failure_backoff.into_inner());
        match &transition {
            Some(Transition::Paused) => trc::event!(
                Ai(AiEvent::ApiError),
                Details = call.model.name().to_string(),
                Reason = format!(
                    "Paused for {}s after repeated failures",
                    limits.failure_backoff.into_inner().as_secs()
                ),
            ),
            Some(Transition::Resumed) => trc::event!(
                Ai(AiEvent::LlmResponse),
                Details = call.model.name().to_string(),
                Reason = "Resumed after a pause",
            ),
            None => {}
        }
        match &result {
            Ok(answer) => match &call.explain {
                // EX-10: an explanation's answer is never logged
                Some(explain) => trc::event!(
                    Ai(AiEvent::LlmResponse),
                    Details = call.model.name().to_string(),
                    AccountId = call.account_id,
                    Elapsed = started.elapsed(),
                    Reason = format!("Explained a {}", explain.subject),
                ),
                None => trc::event!(
                    Ai(AiEvent::LlmResponse),
                    Details = call.model.name().to_string(),
                    AccountId = call.account_id,
                    Elapsed = started.elapsed(),
                    Result = request::cut(answer, 1024),
                ),
            },
            Err(failure) => trc::event!(
                Ai(AiEvent::ApiError),
                Details = call.model.name().to_string(),
                AccountId = call.account_id,
                Elapsed = started.elapsed(),
                Code = match failure {
                    Failure::Status(code) => *code as u64,
                    _ => 0,
                },
                Reason = format!("{failure:?}"),
            ),
        }
        result
    }

    async fn ai_request(&self, call: &Call<'_>) -> Result<String, Failure> {
        let model = call.model;
        let kind = Kind::Chat;
        let endpoint = model.endpoint()?;
        let body = request::body(
            kind,
            model.model(),
            call.system,
            call.user,
            call.temperature,
            call.max_tokens,
            call.stream.is_some(),
        );
        // Secrets are read now, from their source (AI-8)
        let key = model.api_key().secret().await.map_err(Failure::Http)?;
        let mut extra = model.http_headers().clone();
        let bearer = match (model, &key) {
            (AiModel::OpenAi(m), Some(key)) if m.profile == AiOpenAiProfile::Azure => {
                extra.append("api-key".to_string(), key.to_string());
                None
            }
            (_, key) => key.as_deref(),
        };
        let headers = utils::http::build_http_headers(
            extra,
            None,
            None,
            bearer,
            Some("application/json"),
        )
        .map_err(Failure::Http)?;
        let client = utils::http::http_client_builder(model.allow_invalid_certs())
            // A redirect would send content to a host nobody named (AI-8)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(call.timeout)
            .timeout(call.timeout)
            .default_headers(headers)
            .build()
            .map_err(|err| Failure::Http(err.to_string()))?;
        let mut response = client
            .post(&endpoint)
            .body(body.to_string())
            .send()
            .await
            .map_err(|err| {
                if err.is_timeout() {
                    Failure::Timeout
                } else {
                    Failure::Http(err.without_url().to_string())
                }
            })?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(Failure::Status(status));
        }
        if let Some(stream) = &call.stream {
            return read_stream(kind, &mut response, stream).await;
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|err| Failure::Http(err.without_url().to_string()))?
        {
            bytes.extend_from_slice(&chunk);
            if bytes.len() > MAX_RESPONSE_BYTES {
                return Err(Failure::BadAnswer);
            }
        }
        request::answer(kind, &bytes).ok_or(Failure::BadAnswer)
    }

    /// AI-2: warns when a model's endpoint isn't on this network.
    pub async fn ai_warn_if_remote(&self, model: &AiModel) {
        warn_if_remote(model).await
    }
}

/// AI-2: warns when a model's endpoint isn't on this network. Names are
/// resolved; any address outside the local ranges counts.
pub async fn warn_if_remote(model: &AiModel) {
    let url = model.base_url();
    let local = match locality::classify(url) {
        Some(local) => local,
        None => {
            let host = locality::host(url).unwrap_or_default().to_string();
            match tokio::net::lookup_host((host.as_str(), 443)).await {
                Ok(addrs) => {
                    let addrs = addrs.map(|a| a.ip()).collect::<Vec<_>>();
                    !addrs.is_empty()
                        && addrs.into_iter().all(locality::is_local_ip)
                }
                Err(_) => false,
            }
        }
    };
    if !local {
        trc::event!(
            Registry(trc::RegistryEvent::BuildWarning),
            Details = locality::warning(model.name(), url),
        );
    }
}

/// The most of a script's prompt sent (AI-23).
const MAX_PROMPT_BYTES: usize = 32 * 1024;

/// The most of an answer a script gets back (AI-22).
const MAX_SCRIPT_ANSWER_BYTES: usize = 8 * 1024;

/// The longest an account's own script waits (AI-23).
const ACCOUNT_SCRIPT_CEILING: Duration = Duration::from_secs(60);

/// `llm_prompt(model, prompt, temperature)` (AI-20 to AI-25). The answer as
/// plain text, or `None`, which the script sees as `false`.
pub async fn sieve_prompt(
    ctx: crate::scripts::plugins::PluginContext<'_>,
) -> Option<String> {
    use registry::schema::enums::Permission;
    use sieve::runtime::Variable;

    let server = ctx.server;
    let name = ctx.arguments.first()?.to_string();
    let prompt = ctx.arguments.get(1)?.to_string();
    let temperature = match ctx.arguments.get(2) {
        Some(Variable::Float(t)) => Some(*t),
        Some(Variable::Integer(t)) => Some(*t as f64),
        _ => None,
    };

    // AI-23: trusted system scripts always; an account's own with interactAi
    let account_id = match ctx.access_token {
        Some(token) if !token.has_permission(Permission::InteractAi) => {
            trc::event!(
                Ai(AiEvent::ApiError),
                SpanId = ctx.session_id,
                AccountId = token.account_id(),
                Reason = "The account may not call AI models",
            );
            return None;
        }
        Some(token) => Some(token.account_id()),
        None => None,
    };

    let Some((model_id, model)) = server.ai_model_by_name(name.as_ref()).await else {
        trc::event!(
            Ai(AiEvent::ApiError),
            SpanId = ctx.session_id,
            AccountId = account_id,
            Reason = format!("No AI model named {name:?}"),
        );
        return None;
    };
    let limits = server.ai_limits().await;
    let timeout = match account_id {
        Some(_) => model.timeout().min(ACCOUNT_SCRIPT_CEILING),
        None => model.timeout().min(limits.spam_call_ceiling.into_inner()),
    };
    let prompt = request::cut(&prompt, MAX_PROMPT_BYTES);
    let answer = server
        .ai_call(Call {
            model_id,
            model: &model,
            account_id,
            system: None,
            user: &prompt,
            temperature: temperature.or_else(|| model.temperature()),
            max_tokens: request::PROMPT_MAX_TOKENS,
            timeout,
            explain: None,
            stream: None,
        })
        .await
        .ok()?;
    // Plain data: never evaluated (AI-22)
    Some(request::cut(answer.trim(), MAX_SCRIPT_ANSWER_BYTES))
}
