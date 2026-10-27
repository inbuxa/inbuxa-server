/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use encodify::base64::STANDARD;
use std::env;
use std::io::{self, Write};
use store::write::serialize::RawValue;
use store::write::{AnyClass, AnyKey, BatchBuilder, ValueClass};
use store::{IterateParams, Shape, Store, Subspace};

const HELP: &str = concat!(
    "Stalwart Server v",
    env!("CARGO_PKG_VERSION"),
    r#" Data Store CLI

Enter commands (type 'help' for available commands).
"#
);

pub async fn store_console(store: Store) {
    print!("{HELP}");

    if matches!(store, Store::None) {
        println!("No store available. Verify your configuration.");
        return;
    }

    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();

        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "scan" => {
                if parts.len() != 3 {
                    println!("Usage: scan <from_key> <to_key>");
                } else if let (Some(from_key), Some(to_key)) =
                    (parse_key(parts[1]), parse_key(parts[2]))
                {
                    println!("Scanning from {:?} to {:?}", from_key, to_key);
                    let mut from_key = from_key.into_iter();
                    let mut to_key = to_key.into_iter();
                    let (Some(from_subspace), Some(to_subspace)) = (
                        from_key.next().and_then(Subspace::try_from_byte),
                        to_key.next().and_then(Subspace::try_from_byte),
                    ) else {
                        println!("Unknown subspace.");
                        continue;
                    };

                    if from_subspace != to_subspace {
                        println!("Keys must be in the same subspace.");
                        continue;
                    }

                    store
                        .iterate(
                            IterateParams::new(
                                AnyKey {
                                    subspace: from_subspace,
                                    key: from_key.collect::<Vec<_>>(),
                                },
                                AnyKey {
                                    subspace: to_subspace,
                                    key: to_key.collect::<Vec<_>>(),
                                },
                            )
                            .set_values(!matches!(from_subspace.shape(), Shape::Presence)),
                            |key, value| {
                                print!("{}", from_subspace.name());
                                print_escaped(key);
                                print!(" : ");
                                print_escaped(value);
                                println!();
                                Ok(true)
                            },
                        )
                        .await
                        .expect("Failed to scan keys");
                }
            }
            "delete" => match (parts.get(1), parts.get(2)) {
                (Some(from_key), Some(to_key)) => {
                    if let (Some(from_key), Some(to_key)) = (parse_key(from_key), parse_key(to_key))
                    {
                        let mut from_key = from_key.into_iter();
                        let mut to_key = to_key.into_iter();

                        let (Some(from_subspace), Some(to_subspace)) = (
                            from_key.next().and_then(Subspace::try_from_byte),
                            to_key.next().and_then(Subspace::try_from_byte),
                        ) else {
                            println!("Unknown subspace.");
                            continue;
                        };
                        let from_key = AnyKey {
                            subspace: from_subspace,
                            key: from_key.collect::<Vec<_>>(),
                        };
                        let to_key = AnyKey {
                            subspace: to_subspace,
                            key: to_key.collect::<Vec<_>>(),
                        };

                        if from_key.subspace != to_key.subspace {
                            println!("Keys must be in the same subspace.");
                            continue;
                        }

                        let mut total = 0;
                        store
                            .iterate(
                                IterateParams::new(from_key.clone(), to_key.clone()).no_values(),
                                |_, _| {
                                    total += 1;
                                    Ok(true)
                                },
                            )
                            .await
                            .expect("Failed to scan keys");

                        if total > 0 {
                            print!("Are you sure you want to delete {total} keys? (y/N): ");
                            io::stdout().flush().unwrap();
                            let mut response = String::new();
                            io::stdin().read_line(&mut response).unwrap();
                            if !response.trim().eq_ignore_ascii_case("y") {
                                println!("Aborted.");
                                continue;
                            }

                            store
                                .delete_range(from_key, to_key)
                                .await
                                .expect("Failed to delete keys");
                            println!("Deleted {total} keys.");
                        } else {
                            println!("No keys found.");
                        }
                    }
                }
                (Some(key), None) => {
                    if let Some(key) = parse_key(key) {
                        println!("Deleting key: {:?}", key);
                        let mut key = key.into_iter();
                        let Some(subspace) = key.next().and_then(Subspace::try_from_byte) else {
                            println!("Unknown subspace.");
                            continue;
                        };
                        if let Err(err) = delete_raw_key(&store, subspace, key.collect()).await {
                            println!("Failed to delete key: {}", err);
                        }
                    }
                }
                _ => {
                    println!("Usage: delete <from_key> [<to_key>]");
                }
            },
            "get" => {
                if parts.len() != 2 {
                    println!("Usage: get <key>");
                } else if let Some(key) = parse_key(parts[1]) {
                    let mut key = key.into_iter();
                    let Some(subspace) = key.next().and_then(Subspace::try_from_byte) else {
                        println!("Unknown subspace.");
                        continue;
                    };
                    match store
                        .get_value::<RawValue>(AnyKey {
                            subspace,
                            key: key.collect::<Vec<_>>(),
                        })
                        .await
                    {
                        Ok(Some(data)) => {
                            print_escaped(&data.0);
                            println!();
                        }
                        Ok(None) => {
                            println!("Key not found.");
                        }
                        Err(err) => {
                            println!("Failed to retrieve key: {}", err);
                        }
                    }
                }
            }
            "put" => {
                if parts.len() < 2 {
                    println!("Usage: put <key> [<value>]");
                } else if let Some(key) = parse_key(parts[1]) {
                    let value = match parts.get(2) {
                        Some(value) => match parse_value(value) {
                            Some(value) => value,
                            None => continue,
                        },
                        None => Vec::new(),
                    };
                    println!("Putting key: {key:?}");

                    let mut key = key.into_iter();
                    let Some(subspace) = key.next().and_then(Subspace::try_from_byte) else {
                        println!("Unknown subspace.");
                        continue;
                    };
                    if let Err(err) = put_raw_key(&store, subspace, key.collect(), value).await {
                        println!("Failed to insert key: {}", err);
                    }
                }
            }
            "help" => {
                print_help();
            }
            "exit" | "quit" => {
                println!("Exiting...");
                break;
            }
            _ => {
                println!("Unknown command. Type 'help' for available commands.");
            }
        }
    }
}

fn parse_key(input: &str) -> Option<Vec<u8>> {
    let result = parse_value(input)?;
    if result
        .first()
        .is_some_and(|ch| Subspace::try_from_byte(*ch).is_some())
    {
        Some(result)
    } else {
        println!("Invalid key: {result:?}");
        None
    }
}

fn parse_value(input: &str) -> Option<Vec<u8>> {
    if let Some(key) = input.strip_prefix("base64:") {
        base64_decode(key)
    } else {
        Some(parse_binary(input))
    }
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    match STANDARD.decode(input) {
        Ok(value) => Some(value),
        Err(err) => {
            println!("Invalid base64 value: {err}");
            None
        }
    }
}

fn parse_binary(input: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('x') => {
                    let hex: String = chars.by_ref().take(2).collect();
                    if hex.len() == 2 {
                        if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                            result.push(byte);
                        } else {
                            result.extend_from_slice(b"\\x");
                            result.extend_from_slice(hex.as_bytes());
                        }
                    } else {
                        result.push(b'\\');
                        result.push(b'x');
                        result.extend_from_slice(hex.as_bytes());
                    }
                }
                Some(other) => {
                    result.push(b'\\');
                    result.push(other as u8);
                }
                None => {
                    result.push(b'\\');
                }
            }
        } else {
            result.push(c as u8);
        }
    }

    result
}

fn print_escaped(bytes: &[u8]) {
    for ch in bytes {
        if ch.is_ascii() && !ch.is_ascii_control() && *ch != b'\\' {
            print!("{}", *ch as char);
        } else {
            print!("\\x{:02x}", ch);
        }
    }
}

pub async fn delete_raw_key(store: &Store, subspace: Subspace, key: Vec<u8>) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    clear_raw_chunks(store, subspace, &key, &mut batch).await?;
    batch.clear(ValueClass::Any(AnyClass { subspace, key }));
    store.write_batch(&mut batch).await.map(|_| ())
}

pub async fn put_raw_key(
    store: &Store,
    subspace: Subspace,
    key: Vec<u8>,
    value: Vec<u8>,
) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    clear_raw_chunks(store, subspace, &key, &mut batch).await?;
    batch.set(ValueClass::Any(AnyClass { subspace, key }), value);
    store.write_batch(&mut batch).await.map(|_| ())
}

async fn clear_raw_chunks(
    store: &Store,
    subspace: Subspace,
    key: &[u8],
    batch: &mut BatchBuilder,
) -> trc::Result<()> {
    let Some(chunk_size) = store.chunk_size() else {
        return Ok(());
    };
    let is_chunked = store
        .get_value::<RawValue>(AnyKey { subspace, key })
        .await?
        .is_some_and(|value| value.0.len() >= chunk_size);
    if !is_chunked {
        return Ok(());
    }

    let mut chunk_key = Vec::with_capacity(key.len() + 1);
    chunk_key.extend_from_slice(key);
    chunk_key.push(0);
    while store
        .key_exists(AnyKey {
            subspace,
            key: chunk_key.as_slice(),
        })
        .await?
    {
        batch.clear(ValueClass::Any(AnyClass {
            subspace,
            key: chunk_key.clone(),
        }));
        match chunk_key.last_mut() {
            Some(last) if *last < u8::MAX => *last += 1,
            _ => break,
        }
    }
    Ok(())
}

fn print_help() {
    println!("Available commands:");
    println!("  scan <from_key> <to_key>");
    println!("  delete <from_key> [<to_key>]");
    println!("  get <key>");
    println!("  put <key> [<value>]");
    println!("  help");
    println!("  exit/quit");
    println!("Note: Keys and values can be prefixed with 'base64:' for base64 encoding");
    println!("      or use escaped hex values (e.g., \\x41 for 'A')");
}
