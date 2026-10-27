/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, sync::LazyLock, vec::IntoIter};

use jieba_rs::Jieba;

use super::{InnerToken, Token};

pub(crate) static JIEBA: LazyLock<Jieba> = LazyLock::new(Jieba::new);

pub struct ChineseTokenizer<'x, T, I>
where
    T: Iterator<Item = Token<I>>,
    I: InnerToken<'x>,
{
    tokenizer: T,
    tokens: IntoIter<Token<I>>,
    phantom: std::marker::PhantomData<&'x str>,
}

impl<'x, T, I> ChineseTokenizer<'x, T, I>
where
    T: Iterator<Item = Token<I>>,
    I: InnerToken<'x>,
{
    pub fn new(tokenizer: T) -> Self {
        ChineseTokenizer {
            tokenizer,
            tokens: Vec::new().into_iter(),
            phantom: std::marker::PhantomData,
        }
    }
}

impl<'x, T, I> Iterator for ChineseTokenizer<'x, T, I>
where
    T: Iterator<Item = Token<I>>,
    I: InnerToken<'x>,
{
    type Item = Token<I>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(token) = self.tokens.next() {
                return Some(token);
            } else {
                let token = self.tokenizer.next()?;
                if token.word.is_alphabetic_8bit() {
                    let mut token_to = token.from;
                    match token.word.unwrap_alphabetic() {
                        Cow::Borrowed(word) => {
                            self.tokens = JIEBA
                                .cut(word, false)
                                .into_iter()
                                .map(|cut| {
                                    let token_from = token_to;
                                    token_to += cut.word.len();
                                    Token {
                                        word: I::new_alphabetic(cut.word),
                                        from: token_from,
                                        to: token_to,
                                    }
                                })
                                .collect::<Vec<_>>()
                                .into_iter();
                        }
                        Cow::Owned(word) => {
                            self.tokens = JIEBA
                                .cut(&word, false)
                                .into_iter()
                                .map(|cut| {
                                    let token_from = token_to;
                                    token_to += cut.word.len();
                                    Token {
                                        word: I::new_alphabetic(cut.word.to_string()),
                                        from: token_from,
                                        to: token_to,
                                    }
                                })
                                .collect::<Vec<_>>()
                                .into_iter();
                        }
                    }
                } else {
                    return token.into();
                }
            }
        }
    }
}

