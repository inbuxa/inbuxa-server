/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{env, fmt::Write, fs, io, path::Path};

const BMP_WORDS: u32 = 0x10000 / 64;

fn write_table(out: &mut String, name: &str, property: fn(char) -> bool) {
    let _ = write!(out, "static {name}: [u64; {BMP_WORDS}] = [");
    for index in 0..BMP_WORDS {
        let word = (0..64).fold(0u64, |word, bit| {
            if char::from_u32(index * 64 + bit).is_some_and(property) {
                word | (1 << bit)
            } else {
                word
            }
        });
        let _ = write!(out, "{word:#x},");
    }
    out.push_str("];\n");
}

fn main() -> io::Result<()> {
    let mut tables = String::with_capacity(96 * 1024);
    write_table(&mut tables, "ALPHABETIC_BMP", char::is_alphabetic);
    write_table(&mut tables, "ALPHANUMERIC_BMP", char::is_alphanumeric);
    write_table(&mut tables, "UPPERCASE_BMP", char::is_uppercase);

    let out_dir = env::var_os("OUT_DIR").ok_or_else(|| io::Error::other("OUT_DIR is not set"))?;
    fs::write(Path::new(&out_dir).join("unicode_bmp.rs"), tables)?;

    println!("cargo::rustc-check-cfg=cfg(swar_alnum)");
    if matches!(
        env::var("CARGO_CFG_TARGET_ARCH").as_deref(),
        Ok("x86_64" | "aarch64")
    ) {
        println!("cargo::rustc-cfg=swar_alnum");
    }
    println!("cargo::rerun-if-changed=build.rs");
    Ok(())
}
