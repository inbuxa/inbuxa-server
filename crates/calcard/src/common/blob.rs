/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::common::export::EmbeddedBudget;
use ahash::AHashMap;
use std::hash::Hash;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlobIdOutcome<B> {
    Generated(B),
    Declined(Vec<u8>),
    Failed,
}

pub trait BlobIdGenerator<B> {
    fn blob_id(&mut self, data: Vec<u8>, content_type: Option<&str>) -> BlobIdOutcome<B>;

    fn is_enabled(&self) -> bool {
        true
    }
}

pub trait BlobResolver<B> {
    fn resolve(&mut self, blob_id: &B) -> Option<Vec<u8>>;

    fn is_enabled(&self) -> bool {
        true
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NoBlobIds;

#[derive(Debug, Clone, Copy)]
pub struct BlobIdFn<F>(pub F);

#[derive(Debug, Clone, Copy)]
pub struct BlobResolverFn<F>(pub F);

impl<B> BlobIdGenerator<B> for NoBlobIds {
    fn blob_id(&mut self, data: Vec<u8>, _: Option<&str>) -> BlobIdOutcome<B> {
        BlobIdOutcome::Declined(data)
    }

    fn is_enabled(&self) -> bool {
        false
    }
}

impl<B> BlobResolver<B> for NoBlobIds {
    fn resolve(&mut self, _: &B) -> Option<Vec<u8>> {
        None
    }

    fn is_enabled(&self) -> bool {
        false
    }
}

impl<B, F> BlobIdGenerator<B> for BlobIdFn<F>
where
    F: FnMut(&[u8]) -> Option<B>,
{
    fn blob_id(&mut self, data: Vec<u8>, _: Option<&str>) -> BlobIdOutcome<B> {
        match (self.0)(&data) {
            Some(blob_id) => BlobIdOutcome::Generated(blob_id),
            None => BlobIdOutcome::Declined(data),
        }
    }
}

impl<B, F> BlobResolver<B> for BlobResolverFn<F>
where
    F: FnMut(&B) -> Option<Vec<u8>>,
{
    fn resolve(&mut self, blob_id: &B) -> Option<Vec<u8>> {
        (self.0)(blob_id)
    }
}

impl<B, T: BlobIdGenerator<B> + ?Sized> BlobIdGenerator<B> for &mut T {
    fn blob_id(&mut self, data: Vec<u8>, content_type: Option<&str>) -> BlobIdOutcome<B> {
        (**self).blob_id(data, content_type)
    }

    fn is_enabled(&self) -> bool {
        (**self).is_enabled()
    }
}

impl<B, T: BlobResolver<B> + ?Sized> BlobResolver<B> for &mut T {
    fn resolve(&mut self, blob_id: &B) -> Option<Vec<u8>> {
        (**self).resolve(blob_id)
    }

    fn is_enabled(&self) -> bool {
        (**self).is_enabled()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BlobOptions<T = NoBlobIds> {
    handler: Option<T>,
    max_embedded_size: Option<usize>,
}

impl<T> Default for BlobOptions<T> {
    fn default() -> Self {
        Self {
            handler: None,
            max_embedded_size: None,
        }
    }
}

impl<T> BlobOptions<T> {
    pub(crate) fn with_handler<U>(self, handler: U) -> BlobOptions<U> {
        BlobOptions {
            handler: Some(handler),
            max_embedded_size: self.max_embedded_size,
        }
    }

    pub(crate) fn with_max_embedded_size(mut self, max_embedded_size: usize) -> Self {
        self.max_embedded_size = Some(max_embedded_size);
        self
    }

    pub(crate) fn budget(&self) -> EmbeddedBudget {
        EmbeddedBudget::new(self.max_embedded_size)
    }

    pub(crate) fn blob_ids<B: Clone>(&mut self) -> Option<BlobIds<'_, B>>
    where
        T: BlobIdGenerator<B>,
    {
        self.handler
            .as_mut()
            .filter(|generator| BlobIdGenerator::<B>::is_enabled(*generator))
            .map(|generator| BlobIds::new(generator as &mut dyn BlobIdGenerator<B>))
    }

    pub(crate) fn resolved_blobs<B: Clone + Eq + Hash>(&mut self) -> Option<ResolvedBlobs<'_, B>>
    where
        T: BlobResolver<B>,
    {
        self.handler
            .as_mut()
            .filter(|resolver| BlobResolver::<B>::is_enabled(*resolver))
            .map(|resolver| ResolvedBlobs::new(resolver as &mut dyn BlobResolver<B>))
    }
}

pub(crate) struct BlobIds<'a, B> {
    generator: &'a mut dyn BlobIdGenerator<B>,
    expected_sizes: Option<AHashMap<usize, ExpectedSize>>,
    generated: AHashMap<(usize, u64), Vec<GeneratedBinary<B>>>,
    has_failed: bool,
}

#[derive(Default)]
struct ExpectedSize {
    total: usize,
    pending: usize,
}

struct GeneratedBinary<B> {
    blob_id: B,
    data: Vec<u8>,
}

pub(crate) struct GeneratedBlobId<B> {
    pub blob_id: B,
    pub size: usize,
}

impl<'a, B: Clone> BlobIds<'a, B> {
    pub(crate) fn new(generator: &'a mut dyn BlobIdGenerator<B>) -> Self {
        Self {
            generator,
            expected_sizes: None,
            generated: AHashMap::new(),
            has_failed: false,
        }
    }

    pub(crate) fn has_failed(&self) -> bool {
        self.has_failed
    }

    pub(crate) fn expect_sizes(&mut self, sizes: impl IntoIterator<Item = usize>) {
        let expected_sizes = self.expected_sizes.get_or_insert_with(AHashMap::new);
        for size in sizes {
            let expected = expected_sizes.entry(size).or_default();
            expected.total += 1;
            expected.pending += 1;
        }
    }

    pub(crate) fn blob_id(
        &mut self,
        data: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<GeneratedBlobId<B>, Vec<u8>> {
        if data.is_empty() {
            return Err(data);
        }
        let size = data.len();
        let (is_repeated, expects_more) = match &mut self.expected_sizes {
            Some(expected_sizes) => {
                expected_sizes
                    .get_mut(&size)
                    .map_or((false, false), |expected| {
                        expected.pending = expected.pending.saturating_sub(1);
                        (expected.total > 1, expected.pending > 0)
                    })
            }
            None => (true, true),
        };
        if !is_repeated {
            return self.generate(data, content_type);
        }

        let key = (size, self.generated.hasher().hash_one(&data));
        if let Some(generated) = self
            .generated
            .get(&key)
            .and_then(|generated| generated.iter().find(|generated| generated.data == data))
        {
            return Ok(GeneratedBlobId {
                blob_id: generated.blob_id.clone(),
                size,
            });
        }
        if !expects_more {
            return self.generate(data, content_type);
        }
        let blob_id = self.generate(data.clone(), content_type)?.blob_id;
        self.generated
            .entry(key)
            .or_default()
            .push(GeneratedBinary {
                blob_id: blob_id.clone(),
                data,
            });
        Ok(GeneratedBlobId { blob_id, size })
    }

    fn generate(
        &mut self,
        data: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<GeneratedBlobId<B>, Vec<u8>> {
        let size = data.len();
        match self.generator.blob_id(data, content_type) {
            BlobIdOutcome::Generated(blob_id) => Ok(GeneratedBlobId { blob_id, size }),
            BlobIdOutcome::Declined(data) => Err(data),
            BlobIdOutcome::Failed => {
                self.has_failed = true;
                Err(Vec::new())
            }
        }
    }
}

pub(crate) struct ResolvedBlobs<'a, B> {
    resolver: &'a mut dyn BlobResolver<B>,
    uses: AHashMap<B, usize>,
    resolved: AHashMap<B, Option<Vec<u8>>>,
}

impl<'a, B: Clone + Eq + Hash> ResolvedBlobs<'a, B> {
    pub(crate) fn new(resolver: &'a mut dyn BlobResolver<B>) -> Self {
        Self {
            resolver,
            uses: AHashMap::new(),
            resolved: AHashMap::new(),
        }
    }

    pub(crate) fn add_uses<'x>(&mut self, blob_ids: impl Iterator<Item = &'x B>)
    where
        B: 'x,
    {
        for blob_id in blob_ids {
            *self.uses.entry(blob_id.clone()).or_default() += 1;
        }
    }

    pub(crate) fn resolve(&mut self, blob_id: &B) -> Option<Vec<u8>> {
        let remaining = self.uses.get_mut(blob_id).map_or(0, |uses| {
            *uses = uses.saturating_sub(1);
            *uses
        });
        let data = match self.resolved.remove(blob_id) {
            Some(data) => data,
            None => self
                .resolver
                .resolve(blob_id)
                .filter(|data| !data.is_empty()),
        };
        if remaining > 0 {
            self.resolved.insert(blob_id.clone(), data.clone());
        }
        data
    }
}

pub(crate) fn sniff_media_type(data: &[u8]) -> &'static str {
    match data {
        [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, ..] => "image/png",
        [0xFF, 0xD8, 0xFF, ..] => "image/jpeg",
        [b'G', b'I', b'F', b'8', b'7' | b'9', b'a', ..] => "image/gif",
        [
            b'R',
            b'I',
            b'F',
            b'F',
            _,
            _,
            _,
            _,
            b'W',
            b'E',
            b'B',
            b'P',
            ..,
        ] => "image/webp",
        [
            b'R',
            b'I',
            b'F',
            b'F',
            _,
            _,
            _,
            _,
            b'W',
            b'A',
            b'V',
            b'E',
            ..,
        ] => "audio/wav",
        [b'O', b'g', b'g', b'S', ..] => "audio/ogg",
        [b'I', b'D', b'3', ..] | [0xFF, 0xFB | 0xF3 | 0xF2, ..] => "audio/mpeg",
        _ if is_svg(data) => "image/svg+xml",
        _ => "application/octet-stream",
    }
}

fn is_svg(data: &[u8]) -> bool {
    let head = data.get(..data.len().min(512)).unwrap_or_default();
    let text = head.trim_ascii_start();
    (text.starts_with(b"<svg") || text.starts_with(b"<?xml"))
        && head.windows(4).any(|window| window == b"<svg")
}

