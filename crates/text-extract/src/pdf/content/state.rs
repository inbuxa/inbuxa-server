/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::pdf::font::FontId;
use std::hash::{DefaultHasher, Hash, Hasher};

pub(crate) const MAX_SAVED_STATES: usize = 256;
const MAX_COORDINATE: f64 = 1e12;
const PERCENT: f64 = 100.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Matrix {
    pub(crate) a: f64,
    pub(crate) b: f64,
    pub(crate) c: f64,
    pub(crate) d: f64,
    pub(crate) e: f64,
    pub(crate) f: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct TextState {
    pub(crate) char_spacing: f64,
    pub(crate) word_spacing: f64,
    pub(crate) scale: f64,
    pub(crate) leading: f64,
    pub(crate) rise: f64,
    pub(crate) font: FontId,
    pub(crate) size: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct GraphicsState {
    pub(crate) ctm: Matrix,
    pub(crate) text: TextState,
}

#[derive(Debug, Default)]
pub(crate) struct StateStack {
    saved: Vec<GraphicsState>,
    overflow: usize,
    floor: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StackMark {
    saved: usize,
    overflow: usize,
    floor: usize,
}

pub(crate) fn finite(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(-MAX_COORDINATE, MAX_COORDINATE)
    } else {
        0.0
    }
}

impl Matrix {
    pub(crate) const IDENTITY: Matrix = Matrix {
        a: 1.0,
        b: 0.0,
        c: 0.0,
        d: 1.0,
        e: 0.0,
        f: 0.0,
    };

    pub(crate) fn new(values: [f64; 6]) -> Self {
        let [a, b, c, d, e, f] = values.map(finite);
        Matrix { a, b, c, d, e, f }
    }

    #[cfg(all(test, stalwart_tests))]
    pub(crate) fn translation(x: f64, y: f64) -> Self {
        Matrix {
            e: finite(x),
            f: finite(y),
            ..Matrix::IDENTITY
        }
    }

    pub(crate) fn then(&self, next: &Matrix) -> Matrix {
        Matrix {
            a: finite(self.a * next.a + self.b * next.c),
            b: finite(self.a * next.b + self.b * next.d),
            c: finite(self.c * next.a + self.d * next.c),
            d: finite(self.c * next.b + self.d * next.d),
            e: finite(self.e * next.a + self.f * next.c + next.e),
            f: finite(self.e * next.b + self.f * next.d + next.f),
        }
    }

    #[inline]
    pub(crate) fn translate(&mut self, x: f64, y: f64) {
        self.e = finite(self.e + x * self.a + y * self.c);
        self.f = finite(self.f + x * self.b + y * self.d);
    }

    #[cfg(all(test, stalwart_tests))]
    pub(crate) fn apply(&self, x: f64, y: f64) -> (f64, f64) {
        (
            x * self.a + y * self.c + self.e,
            x * self.b + y * self.d + self.f,
        )
    }
}

impl Default for TextState {
    fn default() -> Self {
        TextState {
            char_spacing: 0.0,
            word_spacing: 0.0,
            scale: 1.0,
            leading: 0.0,
            rise: 0.0,
            font: FontId::STANDARD,
            size: 0.0,
        }
    }
}

impl TextState {
    pub(crate) fn set_scale(&mut self, percent: f64) {
        self.scale = finite(percent) / PERCENT;
    }
}

impl GraphicsState {
    pub(crate) fn fingerprint(&self, text: &Matrix, line: &Matrix) -> u64 {
        let mut hasher = DefaultHasher::new();
        for matrix in [&self.ctm, text, line] {
            [matrix.a, matrix.b, matrix.c, matrix.d, matrix.e, matrix.f]
                .map(f64::to_bits)
                .hash(&mut hasher);
        }
        let state = &self.text;
        [
            state.char_spacing,
            state.word_spacing,
            state.scale,
            state.leading,
            state.rise,
            state.size,
        ]
        .map(f64::to_bits)
        .hash(&mut hasher);
        state.font.hash(&mut hasher);
        hasher.finish()
    }
}

impl Default for GraphicsState {
    fn default() -> Self {
        GraphicsState {
            ctm: Matrix::IDENTITY,
            text: TextState::default(),
        }
    }
}

impl StateStack {
    pub(crate) fn clear(&mut self) {
        self.saved.clear();
        self.overflow = 0;
        self.floor = 0;
    }

    pub(crate) fn shrink(&mut self) {
        self.clear();
        self.saved.shrink_to(MAX_SAVED_STATES);
    }

    pub(crate) fn save(&mut self, state: &GraphicsState) {
        if self.saved.len() < MAX_SAVED_STATES {
            self.saved.push(*state);
        } else {
            self.overflow = self.overflow.saturating_add(1);
        }
    }

    pub(crate) fn restore(&mut self, state: &mut GraphicsState) {
        if self.overflow > 0 {
            self.overflow -= 1;
        } else if self.saved.len() > self.floor
            && let Some(saved) = self.saved.pop()
        {
            *state = saved;
        }
    }

    pub(crate) fn enter(&mut self) -> StackMark {
        let mark = StackMark {
            saved: self.saved.len(),
            overflow: self.overflow,
            floor: self.floor,
        };
        self.floor = self.saved.len();
        self.overflow = 0;
        mark
    }

    pub(crate) fn leave(&mut self, mark: StackMark) {
        self.saved.truncate(mark.saved);
        self.overflow = mark.overflow;
        self.floor = mark.floor;
    }
}

