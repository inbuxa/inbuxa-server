/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! What `/set` may store for the classifier and its models (AI-12, AI-18,
//! and the spec's "Errors"): refused with `invalidProperties` naming the
//! field. A model in use can't be destroyed: the registry's foreign key
//! already refuses that, naming `x:SpamAi`.

use jmap_proto::error::set::SetError;
use registry::schema::{
    prelude::{Object, ObjectInner, Property},
    structs::{AiModel, SpamAi},
};
use store::RegistryStore;

fn refuse(property: Property, why: &str) -> SetError<Property> {
    SetError::invalid_properties()
        .with_property(property)
        .with_description(why.to_string())
}

fn temperature_ok(t: f64) -> bool {
    t.is_finite() && (0.0..=1.0).contains(&t)
}

/// Checks an `x:SpamAi` or `x:AiModel` being written.
pub async fn check(registry: &RegistryStore, new: &Object) -> trc::Result<Result<(), SetError<Property>>> {
    match &new.inner {
        ObjectInner::SpamAi(spam_ai) => {
            if let SpamAi::Enable(settings) = spam_ai.as_ref() {
                for tier in settings.tiers.iter() {
                    if registry.object::<AiModel>(tier.model_id).await?.is_none() {
                        return Ok(Err(refuse(Property::ModelId, "No AI model has this id.")));
                    }
                }
            }
        }
        ObjectInner::AiModel(model) => {
            let temperature = match model.as_ref() {
                AiModel::OpenAi(model) => model.temperature,
                AiModel::Anthropic(model) => model.temperature,
                AiModel::Gemini(model) => model.temperature,
                AiModel::Ollama(model) => model.temperature,
                AiModel::TypeSafe(_) => None,
            };
            if let Some(temperature) = temperature
                && !temperature_ok(temperature.into_inner())
            {
                return Ok(Err(refuse(
                    Property::Temperature,
                    "The temperature must be from 0.0 to 1.0.",
                )));
            }
        }
        _ => {}
    }
    Ok(Ok(()))
}
