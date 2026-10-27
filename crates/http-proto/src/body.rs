/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use hyper::body::{Body, Bytes, Frame, SizeHint};
use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

pub struct PrefixedBody {
    prefix: Option<Bytes>,
    body: Option<Bytes>,
}

impl PrefixedBody {
    pub fn new(prefix: Bytes, body: Bytes) -> Self {
        PrefixedBody {
            prefix: Some(prefix).filter(|prefix| !prefix.is_empty()),
            body: Some(body).filter(|body| !body.is_empty()),
        }
    }

    pub fn len(&self) -> usize {
        self.prefix.as_ref().map_or(0, Bytes::len) + self.body.as_ref().map_or(0, Bytes::len)
    }

    pub fn is_empty(&self) -> bool {
        self.prefix.is_none() && self.body.is_none()
    }
}

impl Body for PrefixedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        Poll::Ready(
            this.prefix
                .take()
                .or_else(|| this.body.take())
                .map(|chunk| Ok(Frame::data(chunk))),
        )
    }

    fn is_end_stream(&self) -> bool {
        self.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.len() as u64)
    }
}

