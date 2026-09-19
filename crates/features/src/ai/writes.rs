/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! What `/set` may store for the classifier and its models (AI-12, AI-18,
//! and the spec's "Errors"): refused with `invalidProperties` naming the
//! field. A model in use can't be destroyed: the registry's foreign key
//! already refuses that, naming `x:SpamLlm`.

use jmap_proto::error::set::SetError;
use registry::schema::{
    prelude::{Object, ObjectInner, Property},
    structs::{AiModel, SpamLlm},
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

/// Checks an `x:SpamLlm` or `x:AiModel` being written.
pub async fn check(registry: &RegistryStore, new: &Object) -> trc::Result<Result<(), SetError<Property>>> {
    match &new.inner {
        ObjectInner::SpamLlm(SpamLlm::Enable(settings)) => {
            if settings.separator.is_empty() {
                return Ok(Err(refuse(Property::Separator, "The separator can't be empty.")));
            }
            if settings.categories.iter().count() < 2 {
                return Ok(Err(refuse(
                    Property::Categories,
                    "At least two categories are needed.",
                )));
            }
            if !temperature_ok(settings.temperature.into_inner()) {
                return Ok(Err(refuse(
                    Property::Temperature,
                    "The temperature must be from 0.0 to 1.0.",
                )));
            }
            if registry
                .object::<AiModel>(settings.model_id)
                .await?
                .is_none()
            {
                return Ok(Err(refuse(
                    Property::ModelId,
                    "No AI model has this id.",
                )));
            }
        }
        ObjectInner::AiModel(model) => {
            if !temperature_ok(model.temperature.into_inner()) {
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
