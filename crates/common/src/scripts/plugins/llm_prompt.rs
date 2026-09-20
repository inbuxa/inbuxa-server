/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use sieve::{FunctionMap, runtime::Variable};

use super::PluginContext;

pub fn register(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("llm_prompt", plugin_id, 3);
}

// inbuxa: AI-20 to AI-25, `llm_prompt(model, prompt, temperature)`
pub async fn exec(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    Ok(crate::enterprise::llm::sieve_prompt(ctx)
        .await
        .map_or(Variable::from(false), Variable::from))
}
