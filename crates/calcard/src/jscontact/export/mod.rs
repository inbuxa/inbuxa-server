/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::{
        blob::{BlobOptions, BlobResolver, BlobResolverFn, NoBlobIds, ResolvedBlobs},
        export::{EmbeddedBudget, ExportError},
        jsprop::ordered::OrderedMap,
    },
    jscontact::{JSContactId, JSContactProperty, JSContactValue},
    vcard::VCard,
};
use jmap_tools::{Key, Value};
use std::hash::Hash;

pub mod convert;
pub mod entry;
pub mod params;
pub mod props;

#[derive(Default)]
#[allow(clippy::type_complexity)]
struct State<'x, I, B>
where
    I: JSContactId,
    B: JSContactId,
{
    pub(super) vcard: VCard,
    pub(super) converted_props: Vec<(
        Vec<Key<'static, JSContactProperty<I>>>,
        Value<'x, JSContactProperty<I>, JSContactValue<I, B>>,
    )>,
    pub(super) converted_props_count: usize,
    pub(super) converted_heads: OrderedMap<JSContactProperty<I>, ()>,
    pub(super) language: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct ExportOptions<R = NoBlobIds> {
    blobs: BlobOptions<R>,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            blobs: BlobOptions::default(),
        }
    }
}

pub(super) struct ExportContext<'a, B> {
    blobs: Option<ResolvedBlobs<'a, B>>,
    budget: EmbeddedBudget,
    error: Option<ExportError>,
}

impl ExportOptions {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<R> ExportOptions<R> {
    pub fn with_blob_resolver<B, F>(self, blob_resolver: F) -> ExportOptions<BlobResolverFn<F>>
    where
        F: FnMut(&B) -> Option<Vec<u8>>,
    {
        self.with_resolver(BlobResolverFn(blob_resolver))
    }

    pub fn with_resolver<T>(self, blob_resolver: T) -> ExportOptions<T> {
        ExportOptions {
            blobs: self.blobs.with_handler(blob_resolver),
        }
    }

    pub fn max_embedded_size(mut self, max_embedded_size: usize) -> Self {
        self.blobs = self.blobs.with_max_embedded_size(max_embedded_size);
        self
    }

    pub(super) fn context<B: Clone + Eq + Hash>(&mut self) -> ExportContext<'_, B>
    where
        R: BlobResolver<B>,
    {
        ExportContext {
            budget: self.blobs.budget(),
            blobs: self.blobs.resolved_blobs(),
            error: None,
        }
    }
}

impl<B> ExportContext<'_, B> {
    fn fail(&mut self, error: ExportError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    fn embed(&mut self, data: &[u8]) -> bool {
        match self.budget.take(data) {
            Err(error) => {
                self.blobs = None;
                self.fail(error);
                false
            }
            Ok(()) => true,
        }
    }

    fn into_result(self, vcard: VCard) -> Result<VCard, ExportError> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(vcard),
        }
    }
}
