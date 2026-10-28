/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use std::fmt::Display;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Semver(u64);

impl Semver {
    pub fn current() -> Self {
        env!("CARGO_PKG_VERSION").try_into().unwrap()
    }

    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        let mut version: u64 = 0;
        version |= (major as u64) << 32;
        version |= (minor as u64) << 16;
        version |= patch as u64;
        Semver(version)
    }

    pub fn unpack(&self) -> (u16, u16, u16) {
        let version = self.0;
        let major = ((version >> 32) & 0xFFFF) as u16;
        let minor = ((version >> 16) & 0xFFFF) as u16;
        let patch = (version & 0xFFFF) as u16;
        (major, minor, patch)
    }

    pub fn major(&self) -> u16 {
        (self.0 >> 32) as u16
    }

    pub fn minor(&self) -> u16 {
        (self.0 >> 16) as u16
    }

    pub fn patch(&self) -> u16 {
        self.0 as u16
    }

    pub fn is_valid(&self) -> bool {
        self.0 > 0
    }
}

impl AsRef<u64> for Semver {
    fn as_ref(&self) -> &u64 {
        &self.0
    }
}

impl From<u64> for Semver {
    fn from(value: u64) -> Self {
        Semver(value)
    }
}

impl TryFrom<&str> for Semver {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut parts = value.splitn(3, '.');
        let major = parts.next().ok_or(())?.parse().map_err(|_| ())?;
        let minor = parts.next().ok_or(())?.parse().map_err(|_| ())?;
        // inbuxa: a pre-release or build suffix (27.1.0-rc.1) is not part of
        // the number; without this, Semver::current() panics on an RC.
        let patch = parts.next().ok_or(())?;
        let patch = patch
            .split(['-', '+'])
            .next()
            .unwrap_or_default()
            .parse()
            .map_err(|_| ())?;
        Ok(Semver::new(major, minor, patch))
    }
}

impl Display for Semver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (major, minor, patch) = self.unpack();
        write!(f, "{major}.{minor}.{patch}")
    }
}

#[cfg(test)]
mod tests {
    use super::Semver;

    #[test]
    fn parses_release_candidates() {
        assert_eq!(Semver::try_from("27.1.0-rc.1"), Ok(Semver::new(27, 1, 0)));
        assert_eq!(Semver::try_from("27.1.3"), Ok(Semver::new(27, 1, 3)));
        assert_eq!(Semver::try_from("27.1.3+g1234"), Ok(Semver::new(27, 1, 3)));
        assert_eq!(Semver::try_from("27.1"), Err(()));
        assert_eq!(Semver::try_from("27.1.x"), Err(()));
        assert!(Semver::current().is_valid());
        assert!(Semver::new(2026, 10, 28) > Semver::new(27, 1, 0));
    }
}
