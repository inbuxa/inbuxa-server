/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use std::{borrow::Cow, sync::Arc};

use serde::Deserialize;
use sieve::{Compiler, Event, Input, Script, Sieve, runtime::RuntimeError};

use crate::{
    functions,
    handler::Recorder,
    output::{CompileOutput, Diagnostic, RunOutput},
    settings::{KeyValue, Settings},
};

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Request {
    pub scripts: Vec<ScriptSource>,
    pub message: String,
    pub settings: Settings,
    pub seen_ids: Vec<String>,
    pub now: i64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ScriptSource {
    pub name: String,
    pub source: String,
}

impl Request {
    fn compile_all(&self, compiler: &Compiler) -> (Vec<Sieve>, Vec<Diagnostic>) {
        let mut compiled = Vec::with_capacity(self.scripts.len());
        let mut diagnostics = Vec::new();
        for (index, script) in self.scripts.iter().enumerate() {
            match compiler.compile(to_crlf(&script.source).as_bytes()) {
                Ok(sieve) => compiled.push(sieve),
                Err(err) => diagnostics.push(Diagnostic::compile(index, &err)),
            }
        }
        (compiled, diagnostics)
    }

    pub fn compile(&self) -> CompileOutput {
        let compiler = self.settings.compiler(&mut functions::register());
        CompileOutput {
            diagnostics: self.compile_all(&compiler).1,
        }
    }

    pub fn run(&self) -> RunOutput {
        let mut functions = functions::register();
        let compiler = self.settings.compiler(&mut functions);
        let (compiled, diagnostics) = self.compile_all(&compiler);
        if !diagnostics.is_empty() {
            return RunOutput {
                diagnostics,
                ..Default::default()
            };
        }
        let mut compiled = compiled.into_iter().map(Arc::new);
        let Some(main) = compiled.next() else {
            return RunOutput::default();
        };
        // inbuxa: includes are answered from the other tabs, by name, for
        // :personal and :global alike.
        let includes: Vec<(&str, Arc<Sieve>)> = self
            .scripts
            .iter()
            .skip(1)
            .map(|script| script.name.trim())
            .zip(compiled)
            .collect();

        let runtime = self.settings.runtime(&mut functions);
        let raw = to_crlf(&self.message);
        let mut ctx = runtime.filter(raw.as_bytes());
        self.settings.apply(&mut ctx);

        let main_name = self
            .scripts
            .first()
            .map_or("", |script| script.name.trim())
            .to_string();
        let mut input = Input::script(main_name, main);
        let mut recorder = Recorder::new(&self.settings, &self.seen_ids);
        let mut error = None;
        // inbuxa: as the server does, a runtime error is reported and the
        // script carries on.
        while let Some(result) = ctx.run(input) {
            input = match result {
                Ok(Event::IncludeScript { name, .. }) => {
                    let wanted = match &name {
                        Script::Personal(name) | Script::Global(name) => name.as_str(),
                    };
                    match includes.iter().find(|(tab, _)| *tab == wanted) {
                        Some((_, script)) => Input::script(name.clone(), script.clone()),
                        None => Input::False,
                    }
                }
                Ok(event) => recorder.answer(event),
                Err(err) => {
                    if error.is_none() {
                        error = Some(self.runtime_diagnostic(&err));
                    }
                    recorder.after_error = true;
                    Input::True
                }
            };
        }

        let mut global_variables: Vec<KeyValue> = ctx
            .global_variable_names()
            .filter_map(|name| {
                ctx.global_variable(name).map(|value| KeyValue {
                    name: name.to_string(),
                    value: value.to_string().into_owned(),
                })
            })
            .collect();
        global_variables.sort_unstable_by(|a, b| a.name.cmp(&b.name));

        let error_free = error.is_none();
        RunOutput {
            diagnostics,
            error,
            message_changed: ctx.has_message_changed(),
            global_variables,
            events: recorder.events,
            messages: recorder.messages,
            duplicate_ids: if error_free {
                let mut ids = self.seen_ids.clone();
                ids.extend(recorder.new_ids);
                ids.sort_unstable();
                ids.dedup();
                ids
            } else {
                self.seen_ids.clone()
            },
        }
    }

    fn runtime_diagnostic(&self, err: &RuntimeError) -> Diagnostic {
        let mut diagnostic = Diagnostic::runtime(err);
        if let RuntimeError::InvalidInstruction(invalid) = err {
            let line_num = invalid.line_num();
            let name = invalid.name().to_ascii_lowercase();
            let contains_instruction = |source: &str| {
                source
                    .lines()
                    .nth(line_num.saturating_sub(1))
                    .is_some_and(|line| line.to_ascii_lowercase().contains(&name))
            };
            match self
                .scripts
                .iter()
                .position(|script| contains_instruction(&script.source))
            {
                Some(index) => diagnostic.script = index,
                None => {
                    diagnostic.line = 0;
                    diagnostic.column = 0;
                }
            }
        }
        diagnostic
    }
}

pub fn to_crlf(text: &str) -> Cow<'_, str> {
    let bytes = text.as_bytes();
    let needs_fix = bytes
        .iter()
        .enumerate()
        .any(|(pos, &b)| b == b'\n' && (pos == 0 || bytes.get(pos - 1) != Some(&b'\r')));
    if !needs_fix {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + text.len() / 16);
    let mut prev = '\0';
    for ch in text.chars() {
        if ch == '\n' && prev != '\r' {
            out.push('\r');
        }
        out.push(ch);
        prev = ch;
    }
    Cow::Owned(out)
}
