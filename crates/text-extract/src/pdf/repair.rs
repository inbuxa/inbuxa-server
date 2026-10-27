/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    lexer::{Lexer, Token, is_regular, is_whitespace},
    object::{
        Dict, Indirect, ObjRef, Object, keyword_after, keyword_at, skip_container,
        stream_data_start,
    },
    seek::Seek,
    source::Source,
};
use memchr::{memchr2, memmem::Finder};

const TRAILER: &[u8] = b"trailer";
const STREAM: &[u8] = b"stream";
const OBJ: &[u8] = b"obj";
const TRAILER_LEN: u32 = TRAILER.len() as u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Plain,
    XRef,
    ObjStm,
    Catalog,
    PageTree,
    Page,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Found {
    pub(crate) id: ObjRef,
    pub(crate) offset: u32,
    pub(crate) kind: Kind,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Trailer {
    pub(crate) offset: u32,
    pub(crate) end: u32,
}

#[derive(Default)]
pub(crate) struct Scan {
    pub(crate) objects: Vec<Found>,
    pub(crate) trailers: Vec<Trailer>,
}

struct Headers<'a> {
    data: &'a [u8],
    finder: Finder<'static>,
    seek: Seek,
}

impl Kind {
    pub(crate) fn of(dict: Dict<'_>) -> Self {
        let Some(kind) = dict.get(b"Type").and_then(|kind| kind.as_name()) else {
            return if dict.contains(b"Parent") && dict.contains(b"Contents") {
                Kind::Page
            } else {
                Kind::Plain
            };
        };
        hashify::fnc_map!(kind.decoded(),
            b"XRef" => Kind::XRef,
            b"ObjStm" => Kind::ObjStm,
            b"Catalog" => Kind::Catalog,
            b"Pages" => {
                if dict.contains(b"Parent") {
                    Kind::Plain
                } else {
                    Kind::PageTree
                }
            },
            b"Page" => Kind::Page,
            _ => Kind::Plain
        )
    }
}

impl Scan {
    pub(crate) fn run(source: &Source<'_>) -> Self {
        let data = source.data;
        let mut headers = Headers::new(data);
        let mut scan = Scan::default();
        let mut pos = 0usize;
        while let Some(&byte) = data.get(pos) {
            if is_whitespace(byte) {
                pos += 1;
            } else if byte == b'%' {
                pos = memchr2(b'\r', b'\n', data.get(pos..).unwrap_or_default())
                    .map_or(data.len(), |offset| pos + offset);
            } else if byte.is_ascii_digit()
                && pos
                    .checked_sub(1)
                    .and_then(|before| data.get(before))
                    .is_none_or(|&before| !is_regular(before))
            {
                pos = match Indirect::header(data, pos) {
                    Some((id, lexer)) => {
                        let body = lexer.pos();
                        let limit = headers.next(body);
                        let Some(end) = scan.object(source, pos, id, body, limit) else {
                            break;
                        };
                        end
                    }
                    None => run_end(data, pos),
                };
            } else if is_regular(byte) {
                if keyword_at(data, pos, TRAILER) {
                    scan.trailer(pos, headers.next(pos + TRAILER.len()));
                }
                pos = run_end(data, pos);
            } else {
                pos += 1;
            }
        }
        scan.bound_trailers();
        scan
    }

    fn object(
        &mut self,
        source: &Source<'_>,
        start: usize,
        id: ObjRef,
        body: usize,
        limit: usize,
    ) -> Option<usize> {
        let bounded = source.data.get(..limit.max(body)).unwrap_or(source.data);
        let (kind, end, lexed) = body_end(source, bounded, body);
        if !source.charge_scan(lexed.saturating_sub(body)) {
            return None;
        }
        if let Ok(offset) = u32::try_from(start) {
            self.objects.push(Found { id, offset, kind });
        }
        Some(end.max(body).max(start + 1))
    }

    fn trailer(&mut self, keyword: usize, limit: usize) {
        if let (Ok(offset), Ok(end)) =
            (u32::try_from(keyword + TRAILER.len()), u32::try_from(limit))
        {
            self.trailers.push(Trailer { offset, end });
        }
    }

    fn bound_trailers(&mut self) {
        let mut next_start = u32::MAX;
        for trailer in self.trailers.iter_mut().rev() {
            trailer.end = trailer.end.min(next_start);
            next_start = trailer.offset.saturating_sub(TRAILER_LEN);
        }
    }
}

impl Trailer {
    pub(crate) fn dict<'a>(&self, data: &'a [u8]) -> Option<Dict<'a>> {
        let bounded = data.get(..self.end as usize).unwrap_or(data);
        Object::read(&mut Lexer::at(bounded, self.offset as usize), None)?.as_dict()
    }
}

impl<'a> Headers<'a> {
    fn new(data: &'a [u8]) -> Self {
        Headers {
            data,
            finder: Finder::new(OBJ),
            seek: Seek::default(),
        }
    }

    fn next(&mut self, from: usize) -> usize {
        let Headers { data, finder, seek } = self;
        seek.find(from, |from| {
            finder.find_iter(data.get(from..)?).find_map(|offset| {
                Indirect::header_before(data, from + offset).filter(|&start| start >= from)
            })
        })
        .unwrap_or(data.len())
    }
}

fn run_end(data: &[u8], pos: usize) -> usize {
    data.get(pos..)
        .unwrap_or_default()
        .iter()
        .position(|&byte| !is_regular(byte))
        .map_or(data.len(), |offset| pos + offset)
        .max(pos + 1)
}

fn body_end(source: &Source<'_>, bounded: &[u8], body: usize) -> (Kind, usize, usize) {
    let mut lexer = Lexer::at(bounded, body);
    lexer.skip_whitespace();
    let dict_start = lexer.pos();
    if lexer.next() != Some(Token::DictOpen) {
        return (Kind::Plain, dict_start, lexer.pos());
    }
    let (span, closed) = skip_container(&mut lexer);
    if !closed {
        return (Kind::Plain, dict_start + 2, lexer.pos());
    }
    let dict = Dict::new(span, None);
    let kind = Kind::of(dict);
    let after_dict = lexer.pos();
    let Some(after_keyword) = keyword_after(lexer, STREAM) else {
        return (kind, after_dict, after_dict);
    };
    let start = stream_data_start(source.data, after_keyword);
    let length = dict.get(b"Length").and_then(|length| match length {
        Object::Int(value) => Some(value),
        _ => None,
    });
    (
        kind,
        source.stream_end(start, length).unwrap_or(start),
        after_keyword,
    )
}

