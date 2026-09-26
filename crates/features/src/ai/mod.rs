/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! AI spam classification and the LLM Sieve function
//! (`docs/spec/features/ai-spam-classification.md`). Models are the
//! operator's own, reached over the OpenAI-compatible API; nothing is preset
//! and nothing is sent until an administrator configures a model (AI-1).

pub mod answer;
pub mod explain;
pub mod gate;
pub mod limits;
pub mod locality;
pub mod request;
pub mod writes;
