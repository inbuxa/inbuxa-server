/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The product's name, in one place.
//!
//! Every name the server shows people (protocol greetings, the HTTP sign-in
//! realm, the startup banner, calendar product ids, the name mail clients see
//! during setup) comes from here. That keeps the rebrand to a single file when
//! merging upstream releases, instead of a scattering of string edits.
//!
//! These are macros, not constants, so they can be joined into other string
//! literals at compile time with `concat!`.

/// The product name: `INBUXA`.
#[macro_export]
macro_rules! brand {
    () => {
        "inbuxa"
    };
}

/// The server's full name: `INBUXA Server`.
#[macro_export]
macro_rules! brand_server {
    () => {
        concat!($crate::brand!(), " Server")
    };
}

/// The iCalendar and vCard `PRODID`.
#[macro_export]
macro_rules! brand_prodid {
    () => {
        concat!(
            "-//",
            $crate::brand!(),
            "//",
            $crate::brand_server!(),
            "//EN"
        )
    };
}

/// The project's website, given to clients as the support URL (IMAP `ID`).
#[macro_export]
macro_rules! brand_url {
    () => {
        "https://inbuxa.org"
    };
}

/// The public repository the server's source is published in, named in
/// `/.well-known/source`.
#[macro_export]
macro_rules! brand_repository {
    () => {
        "https://git.coffeylabs.org/inbuxa/inbuxa-server"
    };
}

/// The commit this build was made from, as the release build passes it in
/// `INBUXA_REVISION`. A build that wasn't told has none.
pub const BUILD_REVISION: Option<&str> = option_env!("INBUXA_REVISION");

/// Reads one of the server's environment variables by its unprefixed name,
/// such as `RECOVERY_ADMIN`, from `INBUXA_<name>`.
///
/// The upstream prefix isn't read (SPEC §2.4). An install moved over from
/// upstream that still sets it stops here with the variable to rename, rather
/// than starting on defaults the operator didn't choose.
pub fn env_var(name: &str) -> Result<String, std::env::VarError> {
    let found = std::env::var(format!("INBUXA_{name}"));
    if matches!(found, Err(std::env::VarError::NotPresent))
        && let Some(legacy) = legacy_setting(name, |var| std::env::var_os(var).is_some())
    {
        eprintln!(
            "Error: {legacy} is set, but inbuxa reads INBUXA_{name}. Rename it and start again \
             (https://docs.inbuxa.org/install/migrating/)."
        );
        std::process::exit(1);
    }
    found
}

/// inbuxa: K-S2: the secrets the server takes from its environment. Each can
/// come instead from a file that `INBUXA_<name>_FILE` names (a mounted
/// Kubernetes or Docker secret), so it never has to be in the environment.
pub const SECRET_ENV_VARS: &[&str] = &["RECOVERY_ADMIN", "WEBMAIL_CLIENT_SECRET"];

/// inbuxa: K-S2: one of [`SECRET_ENV_VARS`], from `INBUXA_<name>` or from the
/// file `INBUXA_<name>_FILE` names. `Ok(None)` when neither is set. Setting
/// both is refused, as is a file that can't be read or holds nothing; the
/// message names the variable and the path, never the secret.
pub fn secret_env_var(name: &str) -> Result<Option<String>, String> {
    let value = match env_var(name) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(format!("INBUXA_{name} isn't valid UTF-8"));
        }
    };
    let file = match env_var(&format!("{name}_FILE")) {
        Ok(path) => Some(path),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(format!("INBUXA_{name}_FILE isn't valid UTF-8"));
        }
    };
    resolve_secret(name, value, file, |path| std::fs::read_to_string(path))
}

/// Checks every one of [`SECRET_ENV_VARS`] that is set, so a bad `_FILE`
/// stops the server as it starts rather than when the secret is first used.
pub fn check_secret_env_vars() -> Result<(), String> {
    SECRET_ENV_VARS
        .iter()
        .try_for_each(|name| secret_env_var(name).map(|_| ()))
}

fn resolve_secret(
    name: &str,
    value: Option<String>,
    file: Option<String>,
    read: impl Fn(&str) -> std::io::Result<String>,
) -> Result<Option<String>, String> {
    let value = value.filter(|value| !value.is_empty());
    let file = file
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty());
    match (value, file) {
        (Some(_), Some(_)) => Err(format!(
            "INBUXA_{name} and INBUXA_{name}_FILE are both set: set one of them"
        )),
        (Some(value), None) => Ok(Some(value)),
        (None, Some(path)) => {
            let contents = read(&path)
                .map_err(|err| format!("INBUXA_{name}_FILE: can't read {path}: {err}"))?;
            // A secret file usually ends in a newline that isn't the secret's
            let secret = contents.trim_end_matches(['\n', '\r']);
            if secret.is_empty() {
                Err(format!("INBUXA_{name}_FILE: {path} is empty"))
            } else {
                Ok(Some(secret.to_string()))
            }
        }
        (None, None) => Ok(None),
    }
}

/// The environment prefix upstream reads. Only ever used to refuse it.
const LEGACY_ENV_PREFIX: &str = "STALWART";

/// The upstream-prefixed variable for `name`, if it's set.
fn legacy_setting(name: &str, is_set: impl Fn(&str) -> bool) -> Option<String> {
    let legacy = format!("{LEGACY_ENV_PREFIX}_{name}");
    is_set(&legacy).then_some(legacy)
}

/// inbuxa's version as tags, images and `--version` name it: `27.1` for a
/// series, `27.1.3` for its patches, `27.1-rc.1` for a release candidate. It
/// comes from the one version in the workspace Cargo.toml (`27.1.0`, `27.1.3`,
/// `27.1.0-rc.1`), so a release changes that and nothing else.
#[macro_export]
macro_rules! brand_version {
    () => {
        $crate::branding::__display_version!()
    };
}

#[doc(hidden)]
pub use proc_macros::display_version as __display_version;

#[cfg(test)]
mod tests {
    use super::{LEGACY_ENV_PREFIX, legacy_setting, resolve_secret};

    fn read_as(contents: &'static str) -> impl Fn(&str) -> std::io::Result<String> {
        move |_| Ok(contents.to_string())
    }

    #[test]
    fn a_secret_comes_from_the_variable_or_its_file() {
        let none = |_: &str| -> std::io::Result<String> { panic!("no file to read") };
        assert_eq!(resolve_secret("X", None, None, none), Ok(None));
        assert_eq!(
            resolve_secret("X", Some("s3cret".into()), None, none),
            Ok(Some("s3cret".into()))
        );
        // The file's trailing newline isn't part of the secret; other space is
        assert_eq!(
            resolve_secret("X", None, Some("/run/s".into()), read_as(" s3 cret \r\n\n")),
            Ok(Some(" s3 cret ".into()))
        );
        // An empty variable counts as unset
        assert_eq!(
            resolve_secret(
                "X",
                Some(String::new()),
                Some("/run/s".into()),
                read_as("f")
            ),
            Ok(Some("f".into()))
        );
    }

    #[test]
    fn a_secret_set_twice_or_from_a_bad_file_is_refused_without_showing_it() {
        let both = resolve_secret(
            "X",
            Some("s3cret".into()),
            Some("/run/s".into()),
            read_as("f"),
        );
        assert_eq!(
            both,
            Err("INBUXA_X and INBUXA_X_FILE are both set: set one of them".into())
        );
        assert_eq!(
            resolve_secret("X", None, Some("/run/s".into()), read_as("\n")),
            Err("INBUXA_X_FILE: /run/s is empty".into())
        );
        let missing = resolve_secret("X", None, Some("/no/such".into()), |path| {
            std::fs::read_to_string(path)
        })
        .unwrap_err();
        assert!(
            missing.starts_with("INBUXA_X_FILE: can't read /no/such: "),
            "{missing}"
        );
    }

    #[test]
    fn a_secret_file_is_read_from_disk() {
        let dir = std::env::temp_dir().join(format!("inbuxa-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        std::fs::write(&path, "from-a-file\n").unwrap();
        let path = path.to_string_lossy().to_string();
        assert_eq!(
            resolve_secret("X", None, Some(path), |p| std::fs::read_to_string(p)),
            Ok(Some("from-a-file".into()))
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_version_is_cargos_without_the_series_zero() {
        let cargo = env!("CARGO_PKG_VERSION");
        let shown = crate::brand_version!();
        assert_eq!(
            cargo,
            match shown.split_once('-') {
                Some((series, pre)) => format!("{series}.0-{pre}"),
                None if shown.matches('.').count() == 1 => format!("{shown}.0"),
                None => shown.to_string(),
            }
        );
        // Usable where a literal is needed.
        let banner: &str = concat!("v", crate::brand_version!());
        assert_eq!(banner, format!("v{shown}"));
    }

    #[test]
    fn an_upstream_setting_is_named_for_renaming() {
        let old = format!("{LEGACY_ENV_PREFIX}_RECOVERY_ADMIN");
        let set = |var: &str| var == old;
        assert_eq!(legacy_setting("RECOVERY_ADMIN", set), Some(old.clone()));
        assert_eq!(legacy_setting("HOSTNAME", set), None);
    }
}
