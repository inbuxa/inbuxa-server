/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use sieve::{FunctionMap, runtime::Variable};

use super::PluginContext;


pub fn register(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("llm_prompt", plugin_id, 3);
}

#[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
pub async fn exec(ctx: PluginContext<'_>) -> trc::Result<Variable<'static>> {

    Ok(false.into())
}
