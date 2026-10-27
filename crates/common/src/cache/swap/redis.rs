/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    SwapKey,
    pointer::{ChunkAssembler, ChunkLayout, MAX_CALL_BYTES, SwapPointer, index_batches},
};
use store::{InMemoryStore, backend::redis::RedisStore, rand};
use trc::AddContext;

const LOAD_ATTEMPTS: usize = 2;
const MIN_CHUNK_SIZE: u64 = 4096;
const MAX_KEYS_PER_CALL: u32 = 1024;

pub struct RedisSwapStore {
    store: InMemoryStore,
    chunk_size: u32,
    retention: u64,
    max_size: usize,
}

struct RedisKeys {
    base: String,
}

impl RedisSwapStore {
    pub fn new(store: InMemoryStore, chunk_size: u64, retention: u64, max_size: u64) -> Self {
        RedisSwapStore {
            store,
            chunk_size: u32::try_from(chunk_size.max(MIN_CHUNK_SIZE)).unwrap_or(u32::MAX),
            retention: retention.max(1),
            max_size: max_size as usize,
        }
    }

    pub async fn load(&self, key: SwapKey) -> trc::Result<Option<Vec<u8>>> {
        let keys = RedisKeys::new(key);
        let redis = self.redis(keys.route())?;
        let mut previous = None;

        for _ in 0..LOAD_ATTEMPTS {
            let Some(pointer) = read_pointer(redis, &keys).await? else {
                return Ok(None);
            };
            if previous == Some(pointer) {
                break;
            }

            let Some((layout, length)) = pointer.chunks().zip(
                usize::try_from(pointer.length())
                    .ok()
                    .filter(|length| *length <= self.max_size),
            ) else {
                return Ok(None);
            };

            if let Some(data) = read_generation(redis, &keys, &pointer, layout, length).await? {
                return Ok(Some(data));
            }

            previous = Some(pointer);
        }

        trc::event!(
            Cache(trc::CacheEvent::SwapMiss),
            AccountId = key.account_id,
            Collection = key.collection.as_str(),
            Details = "Cache snapshot generation in Redis is missing or does not match its pointer",
        );

        Ok(None)
    }

    pub async fn store(&self, key: SwapKey, data: &[u8]) -> trc::Result<()> {
        let keys = RedisKeys::new(key);
        let redis = self.redis(keys.route())?;
        let layout = ChunkLayout::new(data.len() as u64, self.chunk_size).ok_or_else(|| {
            trc::EventType::Cache(trc::CacheEvent::SwapError)
                .into_err()
                .details("Cache snapshot has too many chunks for the Redis swap tier")
                .ctx(trc::Key::Size, data.len())
        })?;
        let generation = rand::random();
        let pointer = SwapPointer::new(rand::random(), generation, data.len() as u64, Some(layout));
        let expires = Some(self.retention);

        let mut items = Vec::with_capacity(layout.chunks_per_batch(MAX_CALL_BYTES) as usize);
        for (range, payload) in layout.split(data, MAX_CALL_BYTES) {
            items.clear();
            items.extend(
                range
                    .zip(payload.chunks(layout.size() as usize))
                    .map(|(index, chunk)| (keys.chunk(generation, index), chunk)),
            );
            redis
                .key_set_many(&items, expires)
                .await
                .caused_by(trc::location!())?;
        }

        let previous = read_pointer(redis, &keys).await?;
        redis
            .key_set_many(&[(keys.pointer(), pointer.encode().as_slice())], expires)
            .await
            .caused_by(trc::location!())?;

        if let Some(previous) = previous.filter(|previous| previous.generation() != generation)
            && let Err(err) = unlink_generation(redis, &keys, &previous).await
        {
            trc::error!(
                err.details("Failed to remove a superseded cache snapshot generation")
                    .ctx(trc::Key::AccountId, key.account_id)
                    .ctx(trc::Key::Collection, key.collection.as_str())
            );
        }

        Ok(())
    }

    pub async fn remove(&self, key: SwapKey) -> trc::Result<()> {
        let keys = RedisKeys::new(key);
        let redis = self.redis(keys.route())?;
        let previous = read_pointer(redis, &keys).await?;

        redis
            .key_unlink_many(&[keys.pointer()])
            .await
            .caused_by(trc::location!())?;

        match previous {
            Some(previous) => unlink_generation(redis, &keys, &previous).await,
            None => Ok(()),
        }
    }

    #[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
    fn redis(&self, route: &[u8]) -> trc::Result<&RedisStore> {
        match &self.store {
            InMemoryStore::Redis(store) => Ok(store),
            _ => Err(unsupported()),
        }
    }
}

async fn read_pointer(redis: &RedisStore, keys: &RedisKeys) -> trc::Result<Option<SwapPointer>> {
    redis
        .key_get_many(&[keys.pointer()])
        .await
        .caused_by(trc::location!())
        .map(|values| {
            values
                .into_iter()
                .next()
                .flatten()
                .as_deref()
                .and_then(SwapPointer::parse)
        })
}

async fn read_generation(
    redis: &RedisStore,
    keys: &RedisKeys,
    pointer: &SwapPointer,
    layout: ChunkLayout,
    length: usize,
) -> trc::Result<Option<Vec<u8>>> {
    let mut assembler = ChunkAssembler::new(layout, length);
    let mut batch = Vec::with_capacity(layout.chunks_per_batch(MAX_CALL_BYTES) as usize);

    for range in layout.batches(MAX_CALL_BYTES) {
        batch.clear();
        batch.extend(range.map(|index| keys.chunk(pointer.generation(), index)));

        for chunk in redis
            .key_get_many(&batch)
            .await
            .caused_by(trc::location!())?
        {
            match chunk {
                Some(chunk) if assembler.push(&chunk) => (),
                _ => return Ok(None),
            }
        }
    }

    Ok(assembler.finish())
}

async fn unlink_generation(
    redis: &RedisStore,
    keys: &RedisKeys,
    pointer: &SwapPointer,
) -> trc::Result<()> {
    let Some(layout) = pointer.chunks() else {
        return Ok(());
    };

    let mut batch = Vec::with_capacity(layout.count().min(MAX_KEYS_PER_CALL) as usize);
    for range in index_batches(layout.count(), MAX_KEYS_PER_CALL) {
        batch.clear();
        batch.extend(range.map(|index| keys.chunk(pointer.generation(), index)));
        redis
            .key_unlink_many(&batch)
            .await
            .caused_by(trc::location!())?;
    }

    Ok(())
}

impl RedisKeys {
    fn new(key: SwapKey) -> Self {
        RedisKeys {
            base: format!(
                "{{swap:{}:{}:{}}}",
                key.account_id,
                u8::from(key.collection),
                key.part.code()
            ),
        }
    }

    fn route(&self) -> &[u8] {
        self.base.as_bytes()
    }

    fn pointer(&self) -> Vec<u8> {
        format!("{}:p", self.base).into_bytes()
    }

    fn chunk(&self, generation: u64, index: u32) -> Vec<u8> {
        format!("{}:{generation:x}:{index}", self.base).into_bytes()
    }
}

fn unsupported() -> trc::Error {
    trc::EventType::Cache(trc::CacheEvent::SwapError)
        .into_err()
        .details("The cache swap tier requires a Redis in-memory store")
}

