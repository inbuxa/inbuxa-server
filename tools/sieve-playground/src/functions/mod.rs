/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

// The expression functions an account script can call, compiled from the
// server's own source so the playground cannot drift from it: the modules
// below are the server's files, included by path. misc.rs and unicode.rs
// also hold functions that need crates only the server builds, so the few
// this set uses are copied into `copied`, and a test fails if a copy, the
// list or ApplyString stops matching the server's.

#[path = "../../../../crates/common/src/scripts/functions/array.rs"]
#[allow(dead_code)] // the trusted-only functions
mod array;
mod copied;
#[path = "../../../../crates/common/src/scripts/functions/email.rs"]
#[allow(dead_code)] // the trusted-only functions
mod email;
#[path = "../../../../crates/common/src/scripts/functions/header.rs"]
#[allow(dead_code)] // the trusted-only functions
mod header;
#[path = "../../../../crates/common/src/scripts/functions/text.rs"]
#[allow(dead_code)] // the trusted-only functions
mod text;
#[path = "../../../../crates/common/src/scripts/functions/url.rs"]
#[allow(dead_code)] // the trusted-only functions
mod url;

use sieve::{FunctionMap, runtime::Variable};

use self::{array::*, copied::*, email::*, header::*, text::*, url::*};

/// The server's plugin id and arity for llm_prompt
/// (`crates/common/src/scripts/plugins`). The playground answers it as a
/// server without a model does.
pub const LLM_PROMPT_ID: u32 = 12;

pub fn register() -> FunctionMap {
    let mut functions = register_functions_untrusted();
    functions.set_external_function("llm_prompt", LLM_PROMPT_ID, 3);
    functions
}

pub fn register_functions_untrusted() -> FunctionMap {
    FunctionMap::new()
        .with_function("trim", fn_trim)
        .with_function("trim_start", fn_trim_start)
        .with_function("trim_end", fn_trim_end)
        .with_function("len", fn_len)
        .with_function("count", fn_count)
        .with_function("is_empty", fn_is_empty)
        .with_function("is_number", fn_is_number)
        .with_function("is_ascii", fn_is_ascii)
        .with_function("to_lowercase", fn_to_lowercase)
        .with_function("to_uppercase", fn_to_uppercase)
        .with_function("is_email", fn_is_email)
        .with_function("thread_name", fn_thread_name)
        .with_function("html_to_text", fn_html_to_text)
        .with_function("is_uppercase", fn_is_uppercase)
        .with_function("is_lowercase", fn_is_lowercase)
        .with_function("has_digits", fn_has_digits)
        .with_function("count_spaces", fn_count_spaces)
        .with_function("count_uppercase", fn_count_uppercase)
        .with_function("count_lowercase", fn_count_lowercase)
        .with_function("count_chars", fn_count_chars)
        .with_function("dedup", fn_dedup)
        .with_function("lines", fn_lines)
        .with_function("is_ip_addr", fn_is_ip_addr)
        .with_function("is_ipv4_addr", fn_is_ipv4_addr)
        .with_function("is_ipv6_addr", fn_is_ipv6_addr)
        .with_function("winnow", fn_winnow)
        .with_function_args("sort", fn_sort, 2)
        .with_function_args("email_part", fn_email_part, 2)
        .with_function_args("eq_ignore_case", fn_eq_ignore_case, 2)
        .with_function_args("contains", fn_contains, 2)
        .with_function_args("contains_ignore_case", fn_contains_ignore_case, 2)
        .with_function_args("starts_with", fn_starts_with, 2)
        .with_function_args("ends_with", fn_ends_with, 2)
        .with_function_args("uri_part", fn_uri_part, 2)
        .with_function_args("substring", fn_substring, 3)
        .with_function_args("split", fn_split, 2)
        .with_function_args("rsplit", fn_rsplit, 2)
        .with_function_args("split_once", fn_split_once, 2)
        .with_function_args("rsplit_once", fn_rsplit_once, 2)
        .with_function_args("split_n", fn_split_n, 3)
        .with_function_args("strip_prefix", fn_strip_prefix, 2)
        .with_function_args("strip_suffix", fn_strip_suffix, 2)
        .with_function_args("is_intersect", fn_is_intersect, 2)
}

pub trait ApplyString<'x> {
    fn transform(&self, f: impl Fn(&'_ str) -> Variable) -> Variable;
}

impl ApplyString<'_> for Variable {
    fn transform(&self, f: impl Fn(&'_ str) -> Variable) -> Variable {
        match self {
            Variable::String(s) => f(s),
            Variable::Array(list) => list
                .iter()
                .map(|v| match v {
                    Variable::String(s) => f(s),
                    v => f(v.to_string().as_ref()),
                })
                .collect::<Vec<_>>()
                .into(),
            v => f(v.to_string().as_ref()),
        }
    }
}

#[cfg(test)]
mod tests {
    const SERVER_MOD: &str = include_str!("../../../../crates/common/src/scripts/functions/mod.rs");
    const SERVER_MISC: &str = include_str!("../../../../crates/common/src/scripts/functions/misc.rs");
    const SERVER_UNICODE: &str =
        include_str!("../../../../crates/common/src/scripts/functions/unicode.rs");
    const SERVER_PLUGINS: &str = include_str!("../../../../crates/common/src/scripts/plugins/mod.rs");
    const SERVER_LLM: &str =
        include_str!("../../../../crates/common/src/scripts/plugins/llm_prompt.rs");
    const OURS_MOD: &str = include_str!("mod.rs");
    const OURS_COPIED: &str = include_str!("copied.rs");

    /// The item that starts with `start`, through its closing brace at
    /// column 0.
    fn item<'a>(source: &'a str, start: &str) -> &'a str {
        let from = source
            .find(start)
            .unwrap_or_else(|| panic!("{start} not found"));
        let len = source[from..].find("\n}\n").expect("item end") + 2;
        &source[from..from + len]
    }

    #[test]
    fn function_list_matches_the_server() {
        let start = "pub fn register_functions_untrusted()";
        assert_eq!(item(OURS_MOD, start), item(SERVER_MOD, start));
    }

    #[test]
    fn apply_string_matches_the_server() {
        for start in ["pub trait ApplyString", "impl ApplyString"] {
            assert_eq!(item(OURS_MOD, start), item(SERVER_MOD, start));
        }
    }

    #[test]
    fn copied_functions_match_the_server() {
        for (name, server) in [
            ("fn_is_empty", SERVER_MISC),
            ("fn_is_number", SERVER_MISC),
            ("fn_is_ip_addr", SERVER_MISC),
            ("fn_is_ipv4_addr", SERVER_MISC),
            ("fn_is_ipv6_addr", SERVER_MISC),
            ("fn_is_ascii", SERVER_UNICODE),
        ] {
            let start = format!("pub fn {name}<");
            assert_eq!(item(OURS_COPIED, &start), item(server, &start), "{name}");
        }
    }

    #[test]
    fn llm_prompt_matches_the_server() {
        assert!(SERVER_PLUGINS.contains(&format!(
            "llm_prompt::register({}, &mut self);",
            super::LLM_PROMPT_ID
        )));
        assert!(SERVER_LLM.contains(r#"set_external_function("llm_prompt", plugin_id, 3)"#));
    }

    #[test]
    fn registers_the_server_functions() {
        use sieve::Compiler;
        let script = Compiler::new()
            .register_functions(&mut super::register())
            .compile(
                br#"require ["vnd.inbuxa.expressions", "variables"];
                let "a" "trim(' x ')";
                let "b" "substring('hello', 1, 3)";
                let "c" "split_n('a,b,c', ',', 1)";
                let "d" "uri_part('https://example.org/', 'host')";
                let "e" "is_intersect(['a'], 'a')";
                let "f" "llm_prompt('model', 'prompt', 0.5)";
                "#,
            );
        assert!(script.is_ok(), "{script:?}");
    }
}
