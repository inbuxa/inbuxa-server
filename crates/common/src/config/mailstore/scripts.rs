/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    VERSION_PUBLIC,
    expr::if_block::{BootstrapExprExt, IfBlock},
    scripts::{
        functions::{register_functions_trusted, register_functions_untrusted},
        plugins::RegisterSievePlugins,
    },
};
use ahash::AHashMap;
use registry::{
    schema::{
        prelude::ObjectType,
        structs::{
            SieveSystemInterpreter, SieveSystemScript, SieveUserInterpreter, SieveUserScript,
            SystemSettings,
        },
    },
    types::EnumImpl,
};
use sieve::{Compiler, Runtime, Sieve, compiler::grammar::Capability};
use std::{collections::hash_map::Entry, sync::Arc};
use store::registry::bootstrap::Bootstrap;

pub struct Scripting {
    pub untrusted_compiler: Compiler,
    pub untrusted_runtime: Runtime,
    pub trusted_runtime: Runtime,
    pub trusted_compiler: Compiler,
    pub max_received_headers: usize,
    pub from_addr: IfBlock,
    pub from_name: IfBlock,
    pub return_path: IfBlock,
    pub sign: IfBlock,
    pub untrusted_sign: IfBlock,
    pub trusted_scripts: AHashMap<String, Arc<Sieve>>,
    pub untrusted_scripts: AHashMap<String, Arc<Sieve>>,
    pub http_client: reqwest::Client,
}

impl Scripting {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        // Parse untrusted compiler
        let untrusted = bp.setting_infallible::<SieveUserInterpreter>().await;
        let untrusted_sign = bp.compile_expr(
            ObjectType::SieveUserInterpreter.singleton(),
            &untrusted.ctx_dkim_sign_domain(),
        );
        let mut fnc_map_untrusted = register_functions_untrusted().register_plugins_untrusted();
        let untrusted_compiler = Compiler::new()
            .with_max_script_size(untrusted.max_script_size as usize)
            .with_max_string_size(untrusted.max_string_length as usize)
            .with_max_variable_name_size(untrusted.max_var_name_length as usize)
            .with_max_nested_blocks(untrusted.max_nested_blocks as usize)
            .with_max_nested_tests(untrusted.max_nested_tests as usize)
            .with_max_nested_foreverypart(untrusted.max_nested_for_every as usize)
            .with_max_match_variables(untrusted.max_match_vars as usize)
            .with_max_local_variables(untrusted.max_local_vars as usize)
            .with_max_header_size(untrusted.max_header_size as usize)
            .with_max_includes(untrusted.max_includes as usize)
            .register_functions(&mut fnc_map_untrusted);

        // Parse untrusted runtime
        let mut untrusted_runtime = Runtime::new()
            .with_functions(&mut fnc_map_untrusted)
            .with_max_nested_includes(untrusted.max_nested_includes as usize)
            .with_cpu_limit(untrusted.max_cpu_cycles as usize)
            .with_max_variable_size(untrusted.max_var_size as usize)
            .with_max_redirects(untrusted.max_redirects as usize)
            .with_max_received_headers(usize::MAX) // This is set to usize::MAX here, but the actual limit is enforced during ingestion.
            .with_max_header_size(untrusted.max_header_size as usize)
            .with_max_out_messages(untrusted.max_out_messages as usize)
            .with_default_vacation_expiry(untrusted.default_expiry_vacation.into_inner().as_secs())
            .with_default_duplicate_expiry(
                untrusted.default_expiry_duplicate.into_inner().as_secs(),
            )
            .with_capability(Capability::Expressions)
            .without_capabilities(
                untrusted
                    .disable_capabilities
                    .iter()
                    .map(|cap| cap.as_str()),
            )
            .with_valid_notification_uris(untrusted.allowed_notify_uris)
            .with_protected_headers(untrusted.protected_headers)
            .with_vacation_default_subject(untrusted.default_subject)
            .with_vacation_subject_prefix(untrusted.default_subject_prefix)
            .with_env_variable("name", types::brand_server!())
            .with_env_variable("version", VERSION_PUBLIC)
            .with_env_variable("location", "MS")
            .with_env_variable("phase", "during");

        // Parse trusted compiler and runtime
        let mut fnc_map_trusted = register_functions_trusted().register_plugins_trusted();

        // Allocate compiler and runtime
        let trusted = bp.setting_infallible::<SieveSystemInterpreter>().await;
        let system = bp.setting_infallible::<SystemSettings>().await;
        let local_hostname = if !system.default_hostname.is_empty() {
            system.default_hostname.clone()
        } else {
            bp.registry.local_hostname().to_string()
        };
        let trusted_compiler = Compiler::new()
            .with_max_string_size(52428800)
            .with_max_variable_name_size(100)
            .with_max_nested_blocks(50)
            .with_max_nested_tests(50)
            .with_max_nested_foreverypart(10)
            .with_max_local_variables(8192)
            .with_max_header_size(10240)
            .with_max_includes(10)
            .with_no_capability_check(trusted.no_capability_check)
            .register_functions(&mut fnc_map_trusted);
        let mut trusted_runtime = Runtime::new()
            .without_capabilities([
                Capability::FileInto,
                Capability::Vacation,
                Capability::VacationSeconds,
                Capability::Fcc,
                Capability::Mailbox,
                Capability::MailboxId,
                Capability::MboxMetadata,
                Capability::ServerMetadata,
                Capability::ImapSieve,
                Capability::Duplicate,
            ])
            .with_capability(Capability::Expressions)
            .with_capability(Capability::While)
            .with_max_variable_size(trusted.max_var_size as usize)
            .with_max_header_size(10240)
            .with_valid_notification_uri("mailto")
            .with_functions(&mut fnc_map_trusted)
            .with_max_redirects(trusted.max_redirects as usize)
            .with_max_out_messages(trusted.max_out_messages as usize)
            .with_cpu_limit(trusted.max_cpu_cycles as usize)
            .with_max_nested_includes(trusted.max_nested_includes as usize)
            .with_max_received_headers(trusted.max_received_headers as usize)
            .with_default_duplicate_expiry(trusted.duplicate_expiry.into_inner().as_secs())
            // inbuxa: without it, `environment "name"` answers sieve-rs's default
            .with_env_variable("name", types::brand_server!());
        trusted_runtime.set_local_hostname(local_hostname.clone());
        untrusted_runtime.set_local_hostname(local_hostname);

        // Parse trusted scripts
        let mut trusted_scripts: AHashMap<String, Arc<Sieve>> = AHashMap::new();
        for script in bp.list_infallible::<SieveSystemScript>().await {
            if !script.object.is_active {
                continue;
            }

            match trusted_compiler.compile(script.object.contents.as_bytes()) {
                Ok(compiled) => match trusted_scripts.entry(script.object.name.to_lowercase()) {
                    Entry::Vacant(entry) => {
                        entry.insert(compiled.into());
                    }
                    Entry::Occupied(_) => {
                        bp.build_error(
                            script.id,
                            format!(
                                "Another active system Sieve script is already named {:?}, script names are case insensitive",
                                script.object.name
                            ),
                        );
                    }
                },
                Err(err) => {
                    bp.build_error(
                        script.id,
                        format!("Failed to compile system Sieve script: {err}"),
                    );
                }
            }
        }

        // Parse untrusted scripts
        let mut untrusted_scripts: AHashMap<String, Arc<Sieve>> = AHashMap::new();
        for script in bp.list_infallible::<SieveUserScript>().await {
            if !script.object.is_active {
                continue;
            }

            match untrusted_compiler.compile(script.object.contents.as_bytes()) {
                Ok(compiled) => match untrusted_scripts.entry(script.object.name.to_lowercase()) {
                    Entry::Vacant(entry) => {
                        entry.insert(compiled.into());
                    }
                    Entry::Occupied(_) => {
                        bp.build_error(
                            script.id,
                            format!(
                                "Another active user global Sieve script is already named {:?}, script names are case insensitive",
                                script.object.name
                            ),
                        );
                    }
                },
                Err(err) => {
                    bp.build_error(
                        script.id,
                        format!("Failed to compile user global Sieve script: {err}"),
                    );
                }
            }
        }

        Scripting {
            untrusted_compiler,
            untrusted_runtime,
            trusted_runtime,
            trusted_compiler,
            untrusted_scripts,
            trusted_scripts,
            http_client: utils::http::http_client_builder(cfg!(feature = "test_mode"))
                .pool_max_idle_per_host(0)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            max_received_headers: untrusted.max_received_headers as usize,
            from_addr: bp.compile_expr(
                ObjectType::SieveSystemInterpreter.singleton(),
                &trusted.ctx_default_from_address(),
            ),
            from_name: bp.compile_expr(
                ObjectType::SieveSystemInterpreter.singleton(),
                &trusted.ctx_default_from_name(),
            ),
            return_path: bp.compile_expr(
                ObjectType::SieveSystemInterpreter.singleton(),
                &trusted.ctx_default_return_path(),
            ),
            sign: bp.compile_expr(
                ObjectType::SieveSystemInterpreter.singleton(),
                &trusted.ctx_dkim_sign_domain(),
            ),
            untrusted_sign,
        }
    }

    pub fn trusted_script(&self, name: &str) -> Option<&Arc<Sieve>> {
        script_by_name(&self.trusted_scripts, name)
    }

    pub fn untrusted_script(&self, name: &str) -> Option<&Arc<Sieve>> {
        script_by_name(&self.untrusted_scripts, name)
    }
}

fn script_by_name<'x>(
    scripts: &'x AHashMap<String, Arc<Sieve>>,
    name: &str,
) -> Option<&'x Arc<Sieve>> {
    scripts
        .get(name)
        .or_else(|| scripts.get(name.to_lowercase().as_str()))
}

impl Clone for Scripting {
    fn clone(&self) -> Self {
        Self {
            untrusted_compiler: self.untrusted_compiler.clone(),
            untrusted_runtime: self.untrusted_runtime.clone(),
            trusted_runtime: self.trusted_runtime.clone(),
            from_addr: self.from_addr.clone(),
            from_name: self.from_name.clone(),
            return_path: self.return_path.clone(),
            max_received_headers: self.max_received_headers,
            sign: self.sign.clone(),
            untrusted_sign: self.untrusted_sign.clone(),
            trusted_scripts: self.trusted_scripts.clone(),
            untrusted_scripts: self.untrusted_scripts.clone(),
            trusted_compiler: self.trusted_compiler.clone(),
            http_client: self.http_client.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use sieve::compiler::grammar::Capability;

    // inbuxa: sieve-rs is vendored (vendor/sieve-rs) to carry the fork's
    // name in its Sieve extensions. If Cargo.lock moves sieve-rs past the
    // vendored version, Cargo drops the patch with only a warning and
    // upstream's spelling comes back; this fails instead.
    #[test]
    fn sieve_extensions_carry_the_fork_name() {
        for (capability, name) in [
            (Capability::While, "vnd.inbuxa.while"),
            (Capability::Expressions, "vnd.inbuxa.expressions"),
        ] {
            assert_eq!(capability.to_string(), name);
            assert_eq!(Capability::parse(name), capability);
        }
    }

    // inbuxa: #643: what a shared mailbox's member may save is read from
    // the compiled instructions, not from what the script requires
    #[test]
    fn sieve_sends_mail_reads_the_instructions() {
        let sends = |script: &str| {
            sieve::Compiler::new()
                .compile(script.as_bytes())
                .unwrap_or_else(|err| panic!("{script}: {err}"))
                .sends_mail()
        };
        for script in [
            "redirect \"someone@example.com\";",
            "require \"copy\";\nredirect :copy \"someone@example.com\";",
            "require \"vacation\";\nvacation \"Away.\";",
            "require \"enotify\";\nnotify \"mailto:someone@example.com\";",
            "require \"reject\";\nreject \"Not here.\";",
            "require \"ereject\";\nereject \"Not here.\";",
            // Behind a test, and in a branch that may never run
            "require [\"fileinto\", \"vacation\"];\nif header :contains \"subject\" \"x\" {\n  fileinto \"X\";\n} else {\n  vacation \"Away.\";\n}",
        ] {
            assert!(sends(script), "{script}");
        }
        for script in [
            "keep;",
            "discard;",
            "require \"fileinto\";\nif header :contains \"subject\" \"invoice\" { fileinto \"Billing\"; stop; }",
            "require [\"imap4flags\", \"fileinto\"];\naddflag \"\\\\Seen\";\nfileinto :flags \"\\\\Flagged\" \"Done\";",
            // Required, never used
            "require [\"vacation\", \"enotify\", \"reject\", \"copy\"];\nkeep;",
        ] {
            assert!(!sends(script), "{script}");
        }

        // The same actions compare equal across other edits; a changed
        // argument doesn't
        let actions = |script: &str| {
            sieve::Compiler::new()
                .compile(script.as_bytes())
                .unwrap_or_else(|err| panic!("{script}: {err}"))
                .sending_actions()
        };
        let forward = "require [\"fileinto\", \"copy\", \"vacation\"];\nredirect :copy \"a@example.com\";\nvacation :days 3 \"Away.\";\n";
        let base = actions(forward);
        assert_eq!(base.len(), 3, "{base:?}");
        assert_eq!(
            actions(&format!(
                "{forward}if header :contains \"subject\" \"x\" {{ fileinto \"X\"; }}\n"
            )),
            base
        );
        for changed in [
            forward.replace("a@example.com", "b@example.com"),
            forward.replace(":copy ", ""),
            forward.replace(":days 3", ":days 4"),
            forward.replace("Away.", "Gone."),
        ] {
            assert_ne!(actions(&changed), base, "{changed}");
        }
    }

    // inbuxa: a :regex key compiles to at most 1 MiB; it could take ten
    #[test]
    fn sieve_regexes_are_size_limited() {
        let compile = |pattern: &str| {
            sieve::Compiler::new().compile(
                format!(
                    "require \"regex\";\nif header :regex \"subject\" \"{pattern}\" {{ keep; }}\n"
                )
                .as_bytes(),
            )
        };
        assert!(compile(r"^\\w{20}$").is_ok());
        let err = compile(r"^\\w{200}$").unwrap_err().to_string();
        assert!(err.contains("Invalid regular expression"), "{err}");
    }

    // inbuxa: a pattern built from a variable is compiled once per run, not
    // once for every header it's tested against
    #[test]
    fn sieve_variable_patterns_compile_once() {
        let script = std::sync::Arc::new(
            sieve::Compiler::new()
                .compile(
                    br#"require ["regex", "variables"];
set "p" "^\\w{20}x$";
if header :regex "x-h" "${p}" { discard; }
"#,
                )
                .unwrap(),
        );
        let runtime = sieve::Runtime::new();
        let run = |headers: usize| {
            let mut message = "X-H: value\r\n".repeat(headers);
            message.push_str("Subject: test\r\n\r\nbody\r\n");
            let start = std::time::Instant::now();
            let mut ctx = runtime.filter(message.as_bytes());
            let mut input = sieve::Input::script("test", script.clone());
            while let Some(result) = ctx.run(input) {
                result.unwrap();
                input = sieve::Input::True;
            }
            start.elapsed()
        };
        let one = run(1);
        let many = run(1000);
        assert!(many < one * 10, "1 header: {one:?}, 1000 headers: {many:?}");
    }

    // inbuxa: vacation and notify don't answer mail a program sent (RFC 3834),
    // or two autoresponders answer each other
    #[test]
    fn sieve_auto_submitted_mail_gets_no_reply() {
        let runtime = sieve::Runtime::new();
        let sends = |script: &str, header: &str| {
            let script =
                std::sync::Arc::new(sieve::Compiler::new().compile(script.as_bytes()).unwrap());
            let message = format!(
                "From: sender@example.org\r\nTo: john@example.com\r\n{header}Subject: hi\r\n\r\nbody\r\n"
            );
            let mut ctx = runtime
                .filter(message.as_bytes())
                .with_envelope(sieve::Envelope::From, "sender@example.org")
                .with_envelope(sieve::Envelope::To, "john@example.com")
                .with_user_address("john@example.com");
            let mut input = sieve::Input::script("test", script);
            let mut sent = false;
            while let Some(event) = ctx.run(input) {
                input = match event.unwrap() {
                    sieve::Event::SendMessage { .. } => {
                        sent = true;
                        sieve::Input::True
                    }
                    sieve::Event::DuplicateId { .. } => sieve::Input::False,
                    _ => sieve::Input::True,
                };
            }
            sent
        };
        for script in [
            "require \"vacation\";\nvacation \"away\";\n",
            "require \"enotify\";\nnotify \"mailto:john@example.net\";\n",
        ] {
            assert!(sends(script, ""), "{script}");
            assert!(sends(script, "Auto-Submitted: no\r\n"), "{script}");
            assert!(
                !sends(script, "Auto-Submitted: auto-replied\r\n"),
                "{script}"
            );
            assert!(
                !sends(script, "auto-submitted: auto-generated\r\n"),
                "{script}"
            );
        }
    }

    // inbuxa: #543: no vacation reply to mail the spam filter classified as
    // spam (the 50% the server files into Junk), whatever its headers say
    #[test]
    fn sieve_spam_gets_no_vacation_reply() {
        let runtime = sieve::Runtime::new();
        let script = std::sync::Arc::new(
            sieve::Compiler::new()
                .compile(b"require \"vacation\";\nvacation \"away\";\n")
                .unwrap(),
        );
        let replies = |percentage: Option<u8>| {
            let message =
                "From: sender@example.org\r\nTo: john@example.com\r\nSubject: hi\r\n\r\nbody\r\n";
            let mut ctx = runtime
                .filter(message.as_bytes())
                .with_envelope(sieve::Envelope::From, "sender@example.org")
                .with_envelope(sieve::Envelope::To, "john@example.com")
                .with_user_address("john@example.com")
                .with_spam_status(crate::config::mailstore::spamfilter::spam_status(
                    percentage,
                ));
            let mut input = sieve::Input::script("test", script.clone());
            let mut sent = false;
            while let Some(event) = ctx.run(input) {
                input = match event.unwrap() {
                    sieve::Event::SendMessage { .. } => {
                        sent = true;
                        sieve::Input::True
                    }
                    sieve::Event::DuplicateId { .. } => sieve::Input::False,
                    _ => sieve::Input::True,
                };
            }
            sent
        };
        for percentage in [None, Some(0), Some(25), Some(49)] {
            assert!(replies(percentage), "{percentage:?}");
        }
        for percentage in [Some(50), Some(75), Some(99), Some(100)] {
            assert!(!replies(percentage), "{percentage:?}");
        }
    }

    // inbuxa: a test is true when any key matches (RFC 5229, 5260), whatever
    // the keys' order, and :regex on a date part is a regular expression,
    // not a wildcard pattern
    #[test]
    fn sieve_tests_match_any_key_and_regex_dates() {
        let runtime = sieve::Runtime::new();
        let matched = |test: &str| {
            let script = format!(
                "require [\"fileinto\", \"variables\", \"date\", \"regex\"];\nif {test} {{ fileinto \"matched\"; }}\n"
            );
            let script = std::sync::Arc::new(
                sieve::Compiler::new()
                    .compile(script.as_bytes())
                    .unwrap_or_else(|err| panic!("{test}: {err}")),
            );
            let message = "Date: Tue, 27 Oct 2026 09:30:00 +0000\r\nSubject: hi\r\n\r\nbody\r\n";
            let mut ctx = runtime.filter(message.as_bytes());
            let mut input = sieve::Input::script("test", script);
            let mut filed = false;
            while let Some(event) = ctx.run(input) {
                if let sieve::Event::FileInto { folder, .. } = event.unwrap() {
                    filed |= folder == "matched";
                }
                input = sieve::Input::True;
            }
            filed
        };
        for test in [
            r#"string :is "a" ["a", "b"]"#,
            r#"string :is "a" ["b", "a"]"#,
            r#"string :is ["x", "a"] ["a", "b"]"#,
            r#"date :regex "date" "year" "^20[0-9]{2}$""#,
            r#"date :regex "date" "month" ["^1[12]$", "^10$"]"#,
            r#"date :regex "date" "month" "1.""#,
            r#"currentdate :regex "year" "^[0-9]{4}$""#,
        ] {
            assert!(matched(test), "{test} should match");
        }
        for test in [
            r#"string :is "a" ["b", "c"]"#,
            r#"date :regex "date" "year" "^19[0-9]{2}$""#,
            r#"date :regex "date" "month" "^0[1-9]$""#,
            r#"currentdate :regex "year" "^[0-9]{2}$""#,
        ] {
            assert!(!matched(test), "{test} should not match");
        }
    }

    // inbuxa: replace and enclose inside foreverypart change the message's
    // parts under the loop; the loop and the parts left stay in step, and
    // nothing panics
    #[test]
    fn sieve_replace_inside_foreverypart() {
        let runtime = sieve::Runtime::new();
        let run = |script: &str, message: &str| -> String {
            let script =
                std::sync::Arc::new(sieve::Compiler::new().compile(script.as_bytes()).unwrap());
            let mut ctx = runtime.filter(message.as_bytes());
            let mut input = sieve::Input::script("test", script);
            let mut created = None;
            while let Some(event) = ctx.run(input) {
                if let sieve::Event::CreatedMessage { message, .. } = event.unwrap() {
                    created = Some(String::from_utf8(message).unwrap());
                }
                input = sieve::Input::True;
            }
            created.expect("no message was created")
        };
        let nested = concat!(
            "From: a@example.org\r\nSubject: hi\r\n",
            "Content-Type: multipart/mixed; boundary=\"o\"\r\n\r\n",
            "--o\r\nContent-Type: multipart/mixed; boundary=\"i1\"\r\n",
            "Content-Disposition: attachment; filename=\"a.exe\"\r\n\r\n",
            "--i1\r\nContent-Type: text/plain\r\n\r\npart two\r\n",
            "--i1\r\nContent-Type: text/plain\r\n\r\npart three\r\n",
            "--i1--\r\n",
            "--o\r\nContent-Type: multipart/mixed; boundary=\"i2\"\r\n",
            "Content-Disposition: attachment; filename=\"b.exe\"\r\n\r\n",
            "--i2\r\nContent-Type: text/plain\r\n\r\npart five\r\n",
            "--i2\r\nContent-Type: text/plain\r\n\r\npart six\r\n",
            "--i2--\r\n",
            "--o\r\nContent-Type: text/plain\r\n\r\npart seven\r\n",
            "--o--\r\n"
        );
        let built = run(
            concat!(
                "require [\"foreverypart\", \"mime\", \"replace\"];\n",
                "foreverypart { if header :mime :param \"filename\" :matches ",
                "\"Content-Disposition\" \"*.exe\" { replace \"removed\"; } }\n"
            ),
            nested,
        );
        assert_eq!(built.matches("removed").count(), 2, "{built}");
        for gone in ["part two", "part three", "part five", "part six"] {
            assert!(!built.contains(gone), "{gone} kept: {built}");
        }
        assert!(built.contains("part seven"), "{built}");

        let two_parts = concat!(
            "From: a@example.org\r\nSubject: hi\r\n",
            "Content-Type: multipart/mixed; boundary=\"o\"\r\n\r\n",
            "--o\r\nContent-Type: text/plain\r\n\r\none\r\n",
            "--o\r\nContent-Type: text/plain\r\n\r\ntwo\r\n",
            "--o--\r\n"
        );
        let built = run(
            "require [\"foreverypart\", \"replace\"];\nforeverypart { replace \"x\"; }\n",
            two_parts,
        );
        assert!(!built.contains("two"), "{built}");
        let built = run(
            concat!(
                "require [\"foreverypart\", \"enclose\", \"editheader\"];\n",
                "foreverypart { enclose \"wrapped\"; addheader \"X-Seen\" \"yes\"; }\n"
            ),
            nested,
        );
        assert!(built.contains("wrapped"), "{built}");
    }

    // inbuxa: an inbound Subject that decodes to a CR or LF doesn't add a
    // header to the vacation reply, the notify message or enclose's message
    #[test]
    fn sieve_generated_messages_take_no_header_from_the_subject() {
        let runtime = sieve::Runtime::new();
        // "x\r\nBcc: victim@example.com", RFC 2047 encoded
        let message = concat!(
            "From: sender@example.org\r\nTo: john@example.com\r\n",
            "Subject: =?utf-8?b?eA0KQmNjOiB2aWN0aW1AZXhhbXBsZS5jb20=?=\r\n\r\nbody\r\n"
        );
        for script in [
            "require \"vacation\";\nvacation \"away\";\n",
            "require \"enotify\";\nnotify \"mailto:john@example.net\";\n",
            "require \"enclose\";\nenclose \"wrapped\";\nkeep;\n",
        ] {
            let compiled =
                std::sync::Arc::new(sieve::Compiler::new().compile(script.as_bytes()).unwrap());
            let mut ctx = runtime
                .filter(message.as_bytes())
                .with_envelope(sieve::Envelope::From, "sender@example.org")
                .with_envelope(sieve::Envelope::To, "john@example.com")
                .with_user_address("john@example.com");
            let mut input = sieve::Input::script("test", compiled);
            let mut created = Vec::new();
            while let Some(event) = ctx.run(input) {
                input = match event.unwrap() {
                    sieve::Event::CreatedMessage { message, .. } => {
                        created.push(String::from_utf8(message).unwrap());
                        sieve::Input::True
                    }
                    sieve::Event::DuplicateId { .. } => sieve::Input::False,
                    _ => sieve::Input::True,
                };
            }
            assert_eq!(created.len(), 1, "{script}");
            let headers = created[0].split("\r\n\r\n").next().unwrap();
            assert!(
                headers.contains("Subject: ") && !headers.to_ascii_lowercase().contains("\nbcc:"),
                "{script}{headers}"
            );
        }
    }

    // runs a script against one message and returns the messages it creates
    // and how many it sends
    fn sieve_created_messages(script: &str) -> (Vec<String>, usize) {
        let runtime = sieve::Runtime::new();
        let compiled = std::sync::Arc::new(
            sieve::Compiler::new()
                .compile(script.as_bytes())
                .unwrap_or_else(|err| panic!("{script}: {err}")),
        );
        let message =
            "From: sender@example.org\r\nTo: john@example.com\r\nSubject: hi\r\n\r\nbody\r\n";
        let mut ctx = runtime
            .filter(message.as_bytes())
            .with_envelope(sieve::Envelope::From, "sender@example.org")
            .with_envelope(sieve::Envelope::To, "john@example.com")
            .with_user_address("john@example.com");
        let mut input = sieve::Input::script("test", compiled);
        let mut created = Vec::new();
        let mut sent = 0;
        while let Some(event) = ctx.run(input) {
            input = match event.unwrap() {
                sieve::Event::CreatedMessage { message, .. } => {
                    created.push(String::from_utf8(message).unwrap());
                    sieve::Input::True
                }
                sieve::Event::SendMessage { .. } => {
                    sent += 1;
                    sieve::Input::True
                }
                sieve::Event::DuplicateId { .. } => sieve::Input::False,
                _ => sieve::Input::True,
            };
        }
        (created, sent)
    }

    // inbuxa: #546: one vacation reply per message (RFC 5230, 4.7), however
    // many vacation actions the script reaches
    #[test]
    fn sieve_one_vacation_reply_per_message() {
        for script in [
            "require \"vacation\";\nvacation :handle \"a\" \"away\";\nvacation :handle \"b\" \"still away\";\n",
            concat!(
                "require \"vacation\";\n",
                "if header :contains \"subject\" \"hi\" { vacation :handle \"a\" \"away\"; }\n",
                "if true { vacation :handle \"b\" \"still away\"; }\n",
                "if true { vacation :days 1 \"away again\"; }\n",
            ),
        ] {
            let (created, sent) = sieve_created_messages(script);
            assert_eq!((created.len(), sent), (1, 1), "{script}{created:?}");
            assert!(created[0].ends_with("\r\n\r\naway"), "{}", created[0]);
        }
    }

    // inbuxa: #581: a notify mailto URI doesn't set the header fields RFC 5436
    // (2.7) says to ignore (From, Auto-Submitted, Received, Date, Message-ID)
    // or the ones the server writes about the body itself (X-Sieve,
    // Content-Type, Content-Transfer-Encoding); other URI headers still pass
    #[test]
    fn sieve_notify_mailto_ignores_unsafe_uri_headers() {
        for uri in [
            concat!(
                "mailto:alerts@example.net?auto-submitted=no&received=from%20relay.example.net",
                "&x-sieve=no&content-type=text/html&content-transfer-encoding=base64",
                "&date=Mon,%201%20Jan%202001%2000:00:00%20+0000&message-id=<fixed@example.net>",
                "&from=other@example.net&x-custom=kept"
            ),
            "mailto:alerts@example.net?x-custom=kept&received",
            "mailto:alerts@example.net?x-custom=kept&Auto-Submitted",
        ] {
            let script = format!("require \"enotify\";\nnotify :message \"hi\" \"{uri}\";\n");
            let (created, sent) = sieve_created_messages(&script);
            assert_eq!((created.len(), sent), (1, 1), "{uri}");
            let headers = created[0].split("\r\n\r\n").next().unwrap();
            let lines = |name: &str| {
                headers
                    .split("\r\n")
                    .filter(|line| {
                        line.split_once(':')
                            .is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case(name))
                    })
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                lines("auto-submitted"),
                ["Auto-Submitted: auto-notified"],
                "{uri}\n{headers}"
            );
            assert_eq!(lines("x-sieve"), ["X-Sieve: yes"], "{uri}\n{headers}");
            assert_eq!(
                lines("content-type"),
                ["Content-type: text/plain; charset=utf-8"],
                "{uri}\n{headers}"
            );
            assert_eq!(
                lines("from"),
                ["From: john@example.com"],
                "{uri}\n{headers}"
            );
            for name in ["received", "content-transfer-encoding"] {
                assert!(lines(name).is_empty(), "{uri}\n{headers}");
            }
            let date = lines("date");
            assert!(
                date.len() == 1 && !date[0].contains("2001"),
                "{uri}\n{headers}"
            );
            let message_id = lines("message-id");
            assert!(
                message_id.len() == 1 && !message_id[0].contains("fixed@"),
                "{uri}\n{headers}"
            );
            assert_eq!(lines("x-custom"), ["x-custom: kept"], "{uri}\n{headers}");
        }
    }
}
