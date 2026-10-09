/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

// Copied unchanged from the server's functions/misc.rs and unicode.rs, whose
// other functions need crates the playground does not build. The tests in
// mod.rs compare each one with the server's.

use std::net::IpAddr;

use sieve::{Context, runtime::Variable};

pub fn fn_is_empty<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    match &v[0] {
        Variable::String(s) => s.is_empty(),
        Variable::Integer(_) | Variable::Float(_) => false,
        Variable::Array(a) => a.is_empty(),
    }
    .into()
}

pub fn fn_is_number<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    matches!(&v[0], Variable::Integer(_) | Variable::Float(_)).into()
}

pub fn fn_is_ip_addr<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    v[0].to_string().parse::<std::net::IpAddr>().is_ok().into()
}

pub fn fn_is_ipv4_addr<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| matches!(ip, IpAddr::V4(_)))
        .into()
}

pub fn fn_is_ipv6_addr<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| matches!(ip, IpAddr::V6(_)))
        .into()
}

pub fn fn_is_ascii<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    match &v[0] {
        Variable::String(s) => s.is_ascii(),
        Variable::Integer(_) | Variable::Float(_) => true,
        Variable::Array(a) => a.iter().all(|v| match v {
            Variable::String(s) => s.is_ascii(),
            _ => true,
        }),
    }
    .into()
}
