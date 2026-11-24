/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    KV_RATE_LIMIT_AUTH, KV_RATE_LIMIT_AUTH_LOGIN, KV_RATE_LIMIT_LOITER, KV_RATE_LIMIT_RCPT,
    KV_RATE_LIMIT_RCPT_ADDRESS, KV_RATE_LIMIT_SCAN, Server,
    ipc::{BroadcastEvent, RegistryChange},
    network::{IPV6_PREFIX_MASK, ip_ban_scope, ip_rate_key},
};
use ahash::AHashSet;
use registry::{
    schema::{
        enums::{BlockReason, PasswordHashAlgorithm, PasswordStrength},
        prelude::{Object, ObjectType},
        structs::{self, AllowedIp, BlockedIp, Rate, SystemSettings},
    },
    types::{datetime::UTCDateTime, ipmask::IpAddrOrMask},
};
use std::{fmt::Debug, hash::Hash, net::IpAddr};
use store::{
    registry::{
        bootstrap::Bootstrap,
        write::{RegistryWrite, RegistryWriteResult},
    },
    write::now,
};
use trc::AddContext;
use types::id::Id;
use utils::glob::{GlobPattern, MatchType};
use zxcvbn::Score;

#[derive(Debug, Clone)]
pub struct Security {
    pub allowed_ip_addresses: AHashSet<IpWithTtl<IpAddr>>,
    pub allowed_ip_networks: Vec<IpWithTtl<IpAddrOrMask>>,
    pub has_allowed_networks: bool,
    pub auth_ban_period: Option<u64>,
    pub abuse_ban_period: Option<u64>,
    pub loiter_ban_period: Option<u64>,
    pub scan_ban_period: Option<u64>,

    pub http_banned_paths: Vec<MatchType>,
    pub scanner_fail_rate: Option<Rate>,

    pub auth_fail_rate: Option<Rate>,
    pub rcpt_fail_rate: Option<Rate>,
    pub loiter_fail_rate: Option<Rate>,

    pub default_role_ids_user: Vec<Id>,
    pub default_role_ids_group: Vec<Id>,
    pub default_role_ids_tenant: Vec<Id>,
    pub default_role_ids_admin: Vec<Id>,

    pub password_hash_algorithm: PasswordHashAlgorithm,
    pub password_max_length: u32,
    pub password_min_length: u32,
    pub password_min_strength: Score,
    pub password_default_expiration: Option<u64>,
}

#[derive(Default)]
pub struct BlockedIps {
    pub blocked_ip_addresses: AHashSet<IpWithTtl<IpAddr>>,
    // inbuxa: banned IPv6 /64s, by their upper 64 bits
    pub blocked_ipv6_prefixes: AHashSet<IpWithTtl<u64>>,
    pub blocked_ip_networks: Vec<IpWithTtl<IpAddrOrMask>>,
    pub has_blocked_networks: bool,
}

#[derive(Debug, Clone)]
pub struct IpWithTtl<T: PartialEq + Eq + Hash> {
    pub ip: T,
    pub expires_at: u64,
}

impl Security {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let mut allowed_ip_addresses = AHashSet::new();
        let mut allowed_ip_networks = Vec::new();
        let mut expired_allows = Vec::new();
        let now = now();

        for ip in bp.list_infallible::<AllowedIp>().await {
            let id = ip.id;
            let revision = ip.revision;
            let ip = ip.object;
            let expires_at = ip
                .expires_at
                .as_ref()
                .map(|dt| dt.timestamp() as u64)
                .unwrap_or(u64::MAX);

            if expires_at > now {
                if let Some(ip) = ip.address.try_to_ip() {
                    allowed_ip_addresses.insert(IpWithTtl::new(ip, expires_at));
                } else {
                    let ip_with_ttl = IpWithTtl::new(ip.address, expires_at);

                    if !allowed_ip_networks.contains(&ip_with_ttl) {
                        allowed_ip_networks.push(ip_with_ttl);
                    }
                }
            } else {
                expired_allows.push((
                    id,
                    ip.address.clone(),
                    Object {
                        inner: ip.into(),
                        revision,
                    },
                ));
            }
        }

        // Add proxy protocol IPs as allowed
        let system = bp.setting_infallible::<SystemSettings>().await;
        for ip in system.proxy_trusted_networks {
            if let Some(ip) = ip.try_to_ip() {
                allowed_ip_addresses.insert(IpWithTtl::new(ip, u64::MAX));
            } else {
                let ip_with_ttl = IpWithTtl::new(ip, u64::MAX);
                if !allowed_ip_networks.contains(&ip_with_ttl) {
                    allowed_ip_networks.push(ip_with_ttl);
                }
            }
        }

        if !expired_allows.is_empty() {
            for (id, _, object) in &expired_allows {
                if let Err(err) = bp
                    .registry
                    .write(RegistryWrite::delete_object(*id, object))
                    .await
                {
                    trc::error!(
                        err.details("Failed to delete expired allowed IP from registry.")
                            .caused_by(trc::location!())
                    );
                }
            }

            trc::event!(
                Security(trc::SecurityEvent::IpAllowExpired),
                Details = expired_allows
                    .into_iter()
                    .map(|(_, ip, _)| trc::Value::from(ip.into_inner().0))
                    .collect::<Vec<_>>()
            );
        }

        #[cfg(not(feature = "test_mode"))]
        {
            // Add loopback addresses
            allowed_ip_addresses.insert(IpWithTtl::new(
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                u64::MAX,
            ));
            allowed_ip_addresses.insert(IpWithTtl::new(
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                u64::MAX,
            ));
        }

        let is_recovery_mode = bp.registry.is_recovery_mode();
        let security = bp.setting_infallible::<structs::Security>().await;
        let auth = bp.setting_infallible::<structs::Authentication>().await;
        Security {
            has_allowed_networks: !allowed_ip_networks.is_empty(),
            allowed_ip_addresses,
            allowed_ip_networks,
            auth_ban_period: security.auth_ban_period.map(|v| v.as_secs()),
            abuse_ban_period: security.abuse_ban_period.map(|v| v.as_secs()),
            loiter_ban_period: security.loiter_ban_period.map(|v| v.as_secs()),
            scan_ban_period: security.scan_ban_period.map(|v| v.as_secs()),
            auth_fail_rate: security.auth_ban_rate.filter(|_| !is_recovery_mode),
            rcpt_fail_rate: security.abuse_ban_rate.filter(|_| !is_recovery_mode),
            loiter_fail_rate: security.loiter_ban_rate.filter(|_| !is_recovery_mode),
            http_banned_paths: if is_recovery_mode {
                Vec::new()
            } else {
                security
                    .scan_ban_paths
                    .iter()
                    .map(|pattern| MatchType::Matches(GlobPattern::compile(pattern, true)))
                    .collect()
            },
            scanner_fail_rate: security.scan_ban_rate.filter(|_| !is_recovery_mode),
            default_role_ids_user: auth.default_user_role_ids.into_inner(),
            default_role_ids_group: auth.default_group_role_ids.into_inner(),
            default_role_ids_tenant: auth.default_tenant_role_ids.into_inner(),
            default_role_ids_admin: auth.default_admin_role_ids.into_inner(),
            password_hash_algorithm: auth.password_hash_algorithm,
            password_max_length: auth.password_max_length as u32,
            password_min_length: auth.password_min_length as u32,
            password_min_strength: match auth.password_min_strength {
                PasswordStrength::Zero => Score::Zero,
                PasswordStrength::One => Score::One,
                PasswordStrength::Two => Score::Two,
                PasswordStrength::Three => Score::Three,
                PasswordStrength::Four => Score::Four,
            },
            password_default_expiration: auth.password_default_expiry.map(|v| v.as_secs()),
        }
    }

    fn ban_period(&self, reason: BlockReason) -> Option<u64> {
        match reason {
            BlockReason::RcptToFailure => self.abuse_ban_period,
            BlockReason::AuthFailure => self.auth_ban_period,
            BlockReason::Loitering => self.loiter_ban_period,
            BlockReason::PortScanning => self.scan_ban_period,
            BlockReason::Manual | BlockReason::Other => None,
        }
    }
}

impl Server {
    pub async fn is_rcpt_fail2banned(&self, ip: IpAddr, rcpt: &str) -> trc::Result<bool> {
        if let Some(rate) = &self.core.network.security.rcpt_fail_rate {
            let is_allowed = self.is_ip_allowed(ip)
                || (self
                    .in_memory_store()
                    .is_rate_allowed(KV_RATE_LIMIT_RCPT, &ip_rate_key(&ip), rate, false)
                    .await?
                    .is_none()
                    && self
                        .in_memory_store()
                        .is_rate_allowed(KV_RATE_LIMIT_RCPT_ADDRESS, rcpt.as_bytes(), rate, false)
                        .await?
                        .is_none());

            if !is_allowed {
                return self
                    .block_ip(ip, BlockReason::RcptToFailure)
                    .await
                    .map(|_| true);
            }
        }

        Ok(false)
    }

    pub async fn is_scanner_fail2banned(&self, ip: IpAddr) -> trc::Result<bool> {
        if let Some(rate) = &self.core.network.security.scanner_fail_rate {
            let is_allowed = self.is_ip_allowed(ip)
                || self
                    .in_memory_store()
                    .is_rate_allowed(KV_RATE_LIMIT_SCAN, &ip_rate_key(&ip), rate, false)
                    .await?
                    .is_none();

            if !is_allowed {
                return self
                    .block_ip(ip, BlockReason::PortScanning)
                    .await
                    .map(|_| true);
            }
        }

        Ok(false)
    }

    pub async fn is_http_banned_path(&self, path: &str, ip: IpAddr) -> trc::Result<bool> {
        let paths = &self.core.network.security.http_banned_paths;

        if !paths.is_empty() && paths.iter().any(|p| p.matches(path)) && !self.is_ip_allowed(ip) {
            self.block_ip(ip, BlockReason::PortScanning)
                .await
                .map(|_| true)
        } else {
            Ok(false)
        }
    }

    pub async fn is_loiter_fail2banned(&self, ip: IpAddr) -> trc::Result<bool> {
        if let Some(rate) = &self.core.network.security.loiter_fail_rate {
            let is_allowed = self.is_ip_allowed(ip)
                || self
                    .in_memory_store()
                    .is_rate_allowed(KV_RATE_LIMIT_LOITER, &ip_rate_key(&ip), rate, false)
                    .await?
                    .is_none();

            if !is_allowed {
                return self
                    .block_ip(ip, BlockReason::Loitering)
                    .await
                    .map(|_| true);
            }
        }

        Ok(false)
    }

    pub async fn is_auth_fail2banned(&self, ip: IpAddr, login: Option<&str>) -> trc::Result<bool> {
        if let Some(rate) = &self.core.network.security.auth_fail_rate
            && !self.is_ip_allowed(ip)
        {
            if self
                .in_memory_store()
                .is_rate_allowed(KV_RATE_LIMIT_AUTH, &ip_rate_key(&ip), rate, false)
                .await?
                .is_some()
            {
                return self
                    .block_ip(ip, BlockReason::AuthFailure)
                    .await
                    .map(|_| true);
            }

            // inbuxa: a login's failures from everywhere together ban only
            // the address whose failure went over the limit, and at most
            // until that count starts over. Banning every address that
            // failed on the login after that let anyone who ran a login's
            // count up ban its owner's address on their next typo.
            if let Some(login) = login.filter(|login| !login.is_empty())
                && let Some(window_left) = self
                    .in_memory_store()
                    .is_rate_first_exceeded(KV_RATE_LIMIT_AUTH_LOGIN, login.as_bytes(), rate)
                    .await?
            {
                let period = self
                    .core
                    .network
                    .security
                    .auth_ban_period
                    .map_or(window_left, |period| period.min(window_left));
                return self
                    .block_ip_for(ip, BlockReason::AuthFailure, Some(period))
                    .await
                    .map(|_| true);
            }
        }

        Ok(false)
    }

    /// inbuxa: bans what the failures were counted by, the IPv4 address or
    /// the IPv6 /64 (see `ip_rate_key`)
    pub async fn block_ip(&self, ip: IpAddr, reason: BlockReason) -> trc::Result<()> {
        self.block_address(
            ip_ban_scope(ip),
            reason,
            self.core.network.security.ban_period(reason),
        )
        .await
    }

    /// inbuxa: a ban of this one address for `period` seconds (`None`: no
    /// end)
    pub async fn block_ip_for(
        &self,
        ip: IpAddr,
        reason: BlockReason,
        period: Option<u64>,
    ) -> trc::Result<()> {
        self.block_address(IpAddrOrMask::from_ip(ip.to_canonical()), reason, period)
            .await
    }

    async fn block_address(
        &self,
        address: IpAddrOrMask,
        reason: BlockReason,
        period: Option<u64>,
    ) -> trc::Result<()> {
        // Add IP to blocked list
        let now = now();
        let expires_at = period.map(|v| now + v);
        self.inner
            .data
            .blocked_ips
            .write()
            .insert(address.clone(), expires_at.unwrap_or(u64::MAX));

        // Write blocked IP to config
        // inbuxa: AU-1.10: recorded as the server's automatic ban
        let blocked_ip = Object::from(BlockedIp {
            address,
            created_at: UTCDateTime::from_timestamp(now as i64),
            expires_at: expires_at.map(|ts| UTCDateTime::from_timestamp(ts as i64)),
            reason,
        });
        let id = match inbuxa_features::audit::scope::system(
            "auto-ban",
            self.registry().write(RegistryWrite::insert(&blocked_ip)),
        )
        .await
        .caused_by(trc::location!())?
        {
            RegistryWriteResult::Success(id) => id,
            // inbuxa: the address's earlier ban is still on record (it is
            // removed some time after it ends): the new ban replaces it
            // unless that one lasts longer
            RegistryWriteResult::PrimaryKeyConflict { existing_id, .. }
                if existing_id.object() == ObjectType::BlockedIp =>
            {
                let Some(existing) = self.registry().get(existing_id).await? else {
                    return Ok(());
                };
                let existing_expires_at = BlockedIp::from(existing.clone())
                    .expires_at
                    .map(|dt| dt.timestamp() as u64)
                    .unwrap_or(u64::MAX);
                if existing_expires_at >= expires_at.unwrap_or(u64::MAX) {
                    return Ok(());
                }
                let RegistryWriteResult::Success(id) = inbuxa_features::audit::scope::system(
                    "auto-ban",
                    self.registry().write(RegistryWrite::update(
                        existing_id.id(),
                        &blocked_ip,
                        &existing,
                    )),
                )
                .await
                .caused_by(trc::location!())?
                else {
                    return Ok(());
                };
                id
            }
            _ => return Ok(()),
        };

        // Increment version
        self.cluster_broadcast(BroadcastEvent::RegistryChange(RegistryChange::Insert(
            ObjectType::BlockedIp.id(id),
        )))
        .await;

        Ok(())
    }

    pub fn has_auth_fail2ban(&self) -> bool {
        self.core.network.security.auth_fail_rate.is_some()
    }

    pub fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        self.inner.data.blocked_ips.read().is_blocked(ip) && !self.is_ip_allowed(ip)
    }

    pub fn is_ip_allowed(&self, ip: IpAddr) -> bool {
        self.core
            .network
            .security
            .allowed_ip_addresses
            .get(&IpWithTtl::new(ip, 0))
            .is_some_and(|v| !v.is_expired())
            || (self.core.network.security.has_allowed_networks
                && self
                    .core
                    .network
                    .security
                    .allowed_ip_networks
                    .iter()
                    .any(|network| network.ip.matches(&ip) && !network.is_expired()))
    }

    pub fn is_secure_password(&self, password: &str, user_inputs: &[&str]) -> Result<(), String> {
        if (password.len() as u32) > self.core.network.security.password_max_length {
            Err(format!(
                "Password must be at most {} characters long.",
                self.core.network.security.password_max_length
            ))
        } else if (password.len() as u32) < self.core.network.security.password_min_length {
            Err(format!(
                "Password must be at least {} characters long.",
                self.core.network.security.password_min_length
            ))
        } else if self.core.network.security.password_min_strength > Score::Zero {
            let entropy = zxcvbn::zxcvbn(password, user_inputs);
            if entropy.score() >= self.core.network.security.password_min_strength {
                Ok(())
            } else if let Some(feedback) = entropy.feedback() {
                Err(format!("Password is too weak. {feedback}"))
            } else {
                Err("Password is too weak.".to_string())
            }
        } else {
            Ok(())
        }
    }
}

impl Server {
    /// inbuxa: personal-data catalog, D2: removes bans whose period is over.
    /// They already stop blocking when they expire, and go when settings are
    /// next loaded; the daily clean-up makes sure a server that seldom
    /// reloads doesn't keep them.
    pub async fn purge_expired_blocked_ips(&self) -> trc::Result<()> {
        let now = now() as i64;
        let mut expired = Vec::new();
        for ip in self.registry().list::<BlockedIp>().await? {
            if ip
                .object
                .expires_at
                .as_ref()
                .is_some_and(|at| at.timestamp() <= now)
            {
                let address = ip.object.address.clone();
                let object = Object {
                    inner: ip.object.into(),
                    revision: ip.revision,
                };
                self.registry()
                    .write(RegistryWrite::delete_object(ip.id, &object))
                    .await?;
                expired.push(trc::Value::from(address.into_inner().0));
            }
        }
        if !expired.is_empty() {
            trc::event!(
                Security(trc::SecurityEvent::IpBlockExpired),
                Details = expired
            );
        }
        Ok(())
    }
}

impl BlockedIps {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let mut ips = Self::default();

        if bp.registry.is_recovery_mode() {
            return ips;
        }

        let mut expired_blocks = Vec::new();
        let now = now() as i64;

        for ip in bp.list_infallible::<BlockedIp>().await {
            let id = ip.id;
            let revision = ip.revision;
            let ip = ip.object;
            let expires_at = ip
                .expires_at
                .as_ref()
                .map(|dt| dt.timestamp() as u64)
                .unwrap_or(u64::MAX);

            if ip.expires_at.as_ref().is_none_or(|ip| ip.timestamp() > now) {
                ips.insert(ip.address, expires_at);
            } else {
                expired_blocks.push((
                    id,
                    ip.address.clone(),
                    Object {
                        inner: ip.into(),
                        revision,
                    },
                ));
            }
        }

        if !expired_blocks.is_empty() {
            for (id, _, object) in &expired_blocks {
                if let Err(err) = bp
                    .registry
                    .write(RegistryWrite::delete_object(*id, object))
                    .await
                {
                    trc::error!(
                        err.details("Failed to delete expired blocked IP from registry.")
                            .caused_by(trc::location!())
                    );
                }
            }
            trc::event!(
                Security(trc::SecurityEvent::IpBlockExpired),
                Details = expired_blocks
                    .into_iter()
                    .map(|(_, ip, _)| trc::Value::from(ip.into_inner().0))
                    .collect::<Vec<_>>()
            );
        }

        ips
    }
}

impl BlockedIps {
    /// inbuxa: bans an address, an IPv6 /64 or another network until
    /// `expires_at`, at once, whether at start-up, for a new ban or for one
    /// a peer reported. Of two bans of the same address or /64 the later
    /// is kept: a set keeps the entry it already has, so one whose earlier
    /// ban has ended would otherwise stay unbanned.
    pub fn insert(&mut self, address: IpAddrOrMask, expires_at: u64) {
        match address {
            IpAddrOrMask::V6 { addr, mask } if mask == IPV6_PREFIX_MASK => keep_later(
                &mut self.blocked_ipv6_prefixes,
                IpWithTtl::new(ipv6_prefix(addr), expires_at),
            ),
            address => {
                if let Some(ip) = address.try_to_ip() {
                    keep_later(
                        &mut self.blocked_ip_addresses,
                        IpWithTtl::new(ip.to_canonical(), expires_at),
                    );
                } else {
                    self.blocked_ip_networks
                        .push(IpWithTtl::new(address, expires_at));
                    self.has_blocked_networks = true;
                }
            }
        }
    }

    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.blocked_ip_addresses
            .get(&IpWithTtl::new(ip, 0))
            .is_some_and(|v| !v.is_expired())
            || matches!(ip, IpAddr::V6(v6) if self
                .blocked_ipv6_prefixes
                .get(&IpWithTtl::new(ipv6_prefix(v6), 0))
                .is_some_and(|v| !v.is_expired()))
            || (self.has_blocked_networks
                && self
                    .blocked_ip_networks
                    .iter()
                    .any(|network| network.ip.matches(&ip) && !network.is_expired()))
    }
}

fn ipv6_prefix(ip: std::net::Ipv6Addr) -> u64 {
    (u128::from(ip) >> 64) as u64
}

fn keep_later<T: PartialEq + Eq + Hash>(set: &mut AHashSet<IpWithTtl<T>>, ip: IpWithTtl<T>) {
    if set
        .get(&ip)
        .is_none_or(|existing| existing.expires_at < ip.expires_at)
    {
        set.replace(ip);
    }
}

impl<T: PartialEq + Eq + Hash> Hash for IpWithTtl<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.ip.hash(state);
    }
}

impl<T: PartialEq + Eq + Hash> PartialEq for IpWithTtl<T> {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip
    }
}

impl<T: PartialEq + Eq + Hash> Eq for IpWithTtl<T> {}

impl<T: PartialEq + Eq + Hash> IpWithTtl<T> {
    pub fn new(ip: T, expires_at: u64) -> Self {
        Self { ip, expires_at }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at <= now()
    }
}

#[cfg(test)]
mod tests {
    use super::BlockedIps;
    use crate::network::{ip_ban_scope, ip_rate_key};
    use registry::types::ipmask::IpAddrOrMask;
    use std::net::IpAddr;

    fn ip(ip: &str) -> IpAddr {
        ip.parse().unwrap()
    }

    // inbuxa: one IPv6 host holds a /64, so it is counted and banned as one
    #[test]
    fn ipv6_counted_and_banned_per_64() {
        assert_eq!(
            ip_rate_key(&ip("2001:db8:1:2::10")),
            ip_rate_key(&ip("2001:db8:1:2:ffff:ffff:ffff:ffff"))
        );
        assert_ne!(
            ip_rate_key(&ip("2001:db8:1:2::10")),
            ip_rate_key(&ip("2001:db8:1:3::10"))
        );
        assert_ne!(ip_rate_key(&ip("10.0.0.1")), ip_rate_key(&ip("10.0.0.2")));
        assert_eq!(
            ip_rate_key(&ip("::ffff:10.0.0.1")),
            ip_rate_key(&ip("10.0.0.1"))
        );
        assert_eq!(
            ip_ban_scope(ip("2001:db8:1:2::10")).to_string(),
            "2001:db8:1:2::/64"
        );
        assert_eq!(ip_ban_scope(ip("::ffff:10.0.0.1")).to_string(), "10.0.0.1");

        let mut ips = BlockedIps::default();
        ips.insert(ip_ban_scope(ip("2001:db8:1:2::10")), u64::MAX);
        ips.insert(ip_ban_scope(ip("::ffff:10.0.0.1")), u64::MAX);
        assert!(ips.is_blocked(ip("2001:db8:1:2::99")));
        assert!(!ips.is_blocked(ip("2001:db8:1:3::10")));
        assert!(ips.is_blocked(ip("10.0.0.1")));
        assert!(ips.is_blocked(ip("::ffff:10.0.0.1")));
        assert!(!ips.is_blocked(ip("10.0.0.2")));
        assert!(!ips.has_blocked_networks, "a /64 is looked up, not scanned");
    }

    // inbuxa: a network added to the running list is enforced at once
    #[test]
    fn network_added_at_runtime_blocks() {
        let mut ips = BlockedIps::default();
        assert!(!ips.is_blocked(ip("192.0.2.7")));
        ips.insert("192.0.2.0/24".parse::<IpAddrOrMask>().unwrap(), u64::MAX);
        ips.insert("2001:db8:5::/48".parse::<IpAddrOrMask>().unwrap(), u64::MAX);
        assert!(ips.is_blocked(ip("192.0.2.7")));
        assert!(ips.is_blocked(ip("2001:db8:5:1::1")));
        assert!(!ips.is_blocked(ip("198.51.100.1")));

        // An ended ban doesn't hide a later one of the same /64
        ips.insert("2001:db8:9::/64".parse::<IpAddrOrMask>().unwrap(), 1);
        assert!(!ips.is_blocked(ip("2001:db8:9::1")));
        ips.insert("2001:db8:9::/64".parse::<IpAddrOrMask>().unwrap(), u64::MAX);
        assert!(ips.is_blocked(ip("2001:db8:9::1")));
    }
}
