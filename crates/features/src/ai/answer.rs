/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! From a model's answer to a spam tag (AI-12, AI-13) and the `X-Spam-LLM`
//! header (AI-15). The answer is attacker-influenced text: it only ever
//! selects among the operator's configured categories, and its explanation
//! is sanitized before it reaches a header.

use base64::{Engine, engine::general_purpose::STANDARD};

/// How to read an answer.
#[derive(Debug, Clone)]
pub struct Rules<'x> {
    pub separator: &'x str,
    pub pos_category: usize,
    pub pos_confidence: Option<usize>,
    pub pos_explanation: Option<usize>,
    pub categories: &'x [String],
    pub confidence: &'x [String],
}

/// A classification: its tag and, if any, the model's explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    pub tag: String,
    /// The configured category and confidence the answer named.
    pub category: String,
    pub confidence: Option<String>,
    pub explanation: Option<String>,
}

fn clean(field: &str) -> &str {
    field.trim_matches(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '*' | '.'))
}

fn tag_part(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            let c = c.to_ascii_uppercase();
            if c.is_ascii_uppercase() || c.is_ascii_digit() {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Parses an answer (AI-12). `None` when it names no configured category
/// (or no configured confidence, when one is expected): no tag.
pub fn parse(answer: &str, rules: &Rules<'_>) -> Option<Classified> {
    if rules.separator.is_empty() {
        return None;
    }
    let line = answer.lines().map(str::trim).find(|l| !l.is_empty())?;
    let fields = line.split(rules.separator).collect::<Vec<_>>();
    let pick = |pos: usize, set: &[String]| -> Option<String> {
        let field = clean(fields.get(pos)?);
        set.iter()
            .find(|entry| entry.eq_ignore_ascii_case(field))
            .cloned()
    };
    let category = pick(rules.pos_category, rules.categories)?;
    let mut tag = format!("LLM_{}", tag_part(&category));
    let confidence = match rules.pos_confidence {
        Some(pos) => Some(pick(pos, rules.confidence)?),
        None => None,
    };
    if let Some(confidence) = &confidence {
        tag.push('_');
        tag.push_str(&tag_part(confidence));
    }
    let explanation = rules.pos_explanation.and_then(|pos| {
        let last_used = rules.pos_category.max(rules.pos_confidence.unwrap_or(0));
        let text = if pos > last_used {
            // The last field runs to the end of the line: explanations have commas
            fields.get(pos..).map(|rest| rest.join(rules.separator))
        } else {
            fields.get(pos).map(|f| f.to_string())
        }?;
        let text = text.trim();
        (!text.is_empty()).then(|| text.to_string())
    });
    Some(Classified {
        tag,
        category,
        confidence,
        explanation,
    })
}

/// inbuxa: 1.0's `x:SpamAi` replaced `x:SpamLlm`'s answer format settings
/// with categories and verbal confidence. The answer format is now fixed:
/// `category|confidence|explanation` on one line.
pub const SPAM_AI_SEPARATOR: &str = "|";

/// The confidence words a model answers with, most confident first.
pub const SPAM_AI_CONFIDENCE: [&str; 3] = ["High", "Medium", "Low"];

/// One `x:SpamAiCategory`, as the prompt describes it.
pub struct PromptCategory<'x> {
    pub name: &'x str,
    pub description: &'x str,
    pub includes: Vec<&'x str>,
}

/// The system prompt for `x:SpamAi`: the operator's instructions, the
/// categories, and the answer format the parser reads.
pub fn spam_ai_prompt(
    instructions: &str,
    categories: &[PromptCategory<'_>],
    explanation: bool,
) -> String {
    let mut prompt = instructions.trim_end().to_string();
    if !prompt.is_empty() {
        prompt.push_str("\n\n");
    }
    prompt.push_str("Classify the email into exactly one of these categories:\n");
    for category in categories {
        prompt.push_str("- ");
        prompt.push_str(category.name);
        let description = category.description.trim();
        if !description.is_empty() {
            prompt.push_str(": ");
            prompt.push_str(description);
        }
        if !category.includes.is_empty() {
            prompt.push_str(" (for example: ");
            prompt.push_str(&category.includes.join("; "));
            prompt.push(')');
        }
        prompt.push('\n');
    }
    prompt.push_str(&format!(
        "\nAnswer with a single line: the category name, then {SPAM_AI_SEPARATOR}, then your \
         confidence ({}).",
        SPAM_AI_CONFIDENCE.join(", ")
    ));
    if explanation {
        prompt.push_str(&format!(
            " Then {SPAM_AI_SEPARATOR} and a short explanation of the verdict."
        ));
    }
    prompt
}

/// How an answer is read, for `x:SpamAi`.
pub fn spam_ai_rules<'x>(categories: &'x [String], confidence: &'x [String], explanation: bool) -> Rules<'x> {
    Rules {
        separator: SPAM_AI_SEPARATOR,
        pos_category: 0,
        pos_confidence: Some(1),
        pos_explanation: explanation.then_some(2),
        categories,
        confidence,
    }
}

/// The probability a verbal confidence stands for (`verbalHigh` and so on).
pub fn verbal_probability(confidence: &str, high: f64, medium: f64, low: f64) -> f64 {
    if confidence.eq_ignore_ascii_case("high") {
        high
    } else if confidence.eq_ignore_ascii_case("medium") {
        medium
    } else {
        low
    }
}

/// The tag for a category at a probability (`bucketHigh`, `bucketMedium`):
/// `LLM_<CATEGORY>_<HIGH|MEDIUM|LOW>`, as the bundled rules score them.
pub fn bucket_tag(category: &str, probability: f64, high: f64, medium: f64) -> String {
    let bucket = if probability >= high {
        "HIGH"
    } else if probability >= medium {
        "MEDIUM"
    } else {
        "LOW"
    };
    format!("LLM_{}_{bucket}", tag_part(category))
}

/// Whether a tag is the classifier's (AI-13).
pub fn is_llm_tag(tag: &str) -> bool {
    tag.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("LLM_"))
}

/// A tag's score, clamped (AI-13): the model reads attacker-written text,
/// so it can add at most `max_added` and take off at most `max_subtracted`.
pub fn clamp(score: f32, max_added: f32, max_subtracted: f32) -> f32 {
    score.clamp(-max_subtracted.abs(), max_added.abs())
}

/// The explanation as it may appear in a header: at most 200 characters,
/// with control characters (CR and LF included) and parentheses removed.
pub fn sanitize(explanation: &str) -> String {
    explanation
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '(' | ')'))
        .take(200)
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Encodes non-ASCII text as RFC 2047 encoded words, each at most 75
/// characters, split on character boundaries.
fn encoded_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in text.chars() {
        if chunk.len() + c.len_utf8() > 45 {
            words.push(format!("=?UTF-8?B?{}?=", STANDARD.encode(chunk.as_bytes())));
            chunk.clear();
        }
        chunk.push(c);
    }
    if !chunk.is_empty() {
        words.push(format!("=?UTF-8?B?{}?=", STANDARD.encode(chunk.as_bytes())));
    }
    words
}

/// The `X-Spam-LLM` header line, CRLF included (AI-15): `TAG` or
/// `TAG (explanation)`, the explanation sanitized, RFC 2047-encoded when not
/// ASCII, and folded to RFC 5322's 78-character lines.
pub fn header(tag: &str, explanation: Option<&str>) -> String {
    let mut tokens = vec![tag.to_string()];
    let explanation = explanation.map(sanitize).filter(|e| !e.is_empty());
    if let Some(explanation) = explanation {
        let mut words = if explanation.is_ascii() {
            explanation.split(' ').map(str::to_string).collect::<Vec<_>>()
        } else {
            encoded_words(&explanation)
        };
        if let Some(first) = words.first_mut() {
            first.insert(0, '(');
        }
        if let Some(last) = words.last_mut() {
            last.push(')');
        }
        tokens.extend(words);
    }
    let mut out = String::from("X-Spam-LLM:");
    let mut line_len = out.len();
    for token in tokens {
        if line_len + 1 + token.len() > 78 && line_len > 1 {
            out.push_str("\r\n");
            line_len = 0;
        }
        out.push(' ');
        out.push_str(&token);
        line_len += 1 + token.len();
    }
    out.push_str("\r\n");
    out
}

/// Removes every `X-Spam-LLM` header from a message's header block, so a
/// sender can't plant one (AI-15). `None` when there's none to remove.
pub fn strip_header(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len());
    let mut removed = false;
    let mut skipping = false;
    let mut pos = 0;
    while pos < raw.len() {
        let end = raw[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(raw.len(), |i| pos + i + 1);
        let line = &raw[pos..end];
        if line == b"\r\n" || line == b"\n" {
            // End of the header block: the body is kept as it is
            out.extend_from_slice(&raw[pos..]);
            break;
        }
        let is_continuation = matches!(line.first(), Some(b' ' | b'\t'));
        if !is_continuation {
            skipping = line.len() > 11 && line[..11].eq_ignore_ascii_case(b"x-spam-llm:");
        }
        if skipping {
            removed = true;
        } else {
            out.extend_from_slice(line);
        }
        pos = end;
    }
    removed.then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules<'x>(categories: &'x [String], confidence: &'x [String]) -> Rules<'x> {
        Rules {
            separator: ",",
            pos_category: 0,
            pos_confidence: Some(1),
            pos_explanation: Some(2),
            categories,
            confidence,
        }
    }

    fn sets() -> (Vec<String>, Vec<String>) {
        (
            ["Unsolicited", "Commercial", "Harmful", "Legitimate"]
                .map(String::from)
                .to_vec(),
            ["High", "Medium", "Low"].map(String::from).to_vec(),
        )
    }

    #[test]
    fn parses_answers() {
        let (cats, conf) = sets();
        let r = rules(&cats, &conf);
        assert_eq!(
            parse("Unsolicited,High,Test", &r),
            Some(Classified {
                tag: "LLM_UNSOLICITED_HIGH".into(),
                category: "Unsolicited".into(),
                confidence: Some("High".into()),
                explanation: Some("Test".into())
            })
        );
        // Test 3: spacing, case and commas in the explanation
        assert_eq!(
            parse("\n  unsolicited , HIGH , Lots of commas, here\nmore", &r),
            Some(Classified {
                tag: "LLM_UNSOLICITED_HIGH".into(),
                category: "Unsolicited".into(),
                confidence: Some("High".into()),
                explanation: Some("Lots of commas, here".into())
            })
        );
        assert_eq!(parse("**Harmful**, 'low'.", &r).unwrap().tag, "LLM_HARMFUL_LOW");
        // Test 4: no tag
        for bad in ["Maybe,High,x", "", "no separator here", "Unsolicited,Very"] {
            assert_eq!(parse(bad, &r), None, "{bad}");
        }
        // Test 5: no confidence position
        let r = Rules {
            pos_confidence: None,
            pos_explanation: None,
            ..rules(&cats, &conf)
        };
        assert_eq!(parse("Unsolicited,whatever", &r).unwrap().tag, "LLM_UNSOLICITED");
    }

    #[test]
    fn spam_ai_answers() {
        let cats = ["Unsolicited", "Legitimate"].map(String::from).to_vec();
        let conf = SPAM_AI_CONFIDENCE.map(String::from).to_vec();
        let prompt = spam_ai_prompt(
            "Be careful.",
            &[PromptCategory {
                name: "Unsolicited",
                description: "Bulk mail nobody asked for",
                includes: vec!["cold sales"],
            }],
            true,
        );
        assert!(prompt.starts_with("Be careful.\n\n"));
        assert!(prompt.contains("- Unsolicited: Bulk mail nobody asked for (for example: cold sales)"));
        assert!(prompt.contains("short explanation"));

        let r = spam_ai_rules(&cats, &conf, true);
        let c = parse("legitimate | medium | a known sender", &r).unwrap();
        assert_eq!(c.category, "Legitimate");
        assert_eq!(c.confidence.as_deref(), Some("Medium"));
        assert_eq!(c.explanation.as_deref(), Some("a known sender"));
        let r = spam_ai_rules(&cats, &conf, false);
        assert_eq!(parse("Unsolicited|High|why", &r).unwrap().explanation, None);

        assert_eq!(verbal_probability("HIGH", 0.9, 0.7, 0.5), 0.9);
        assert_eq!(verbal_probability("whatever", 0.9, 0.7, 0.5), 0.5);
        assert_eq!(bucket_tag("Unsolicited", 0.9, 0.85, 0.6), "LLM_UNSOLICITED_HIGH");
        assert_eq!(bucket_tag("Unsolicited", 0.7, 0.85, 0.6), "LLM_UNSOLICITED_MEDIUM");
        assert_eq!(bucket_tag("Unsolicited", 0.5, 0.85, 0.6), "LLM_UNSOLICITED_LOW");
    }

    #[test]
    fn clamps() {
        assert_eq!(clamp(50.0, 5.0, 1.0), 5.0);
        assert_eq!(clamp(-50.0, 5.0, 1.0), -1.0);
        assert_eq!(clamp(2.0, 5.0, 1.0), 2.0);
    }

    #[test]
    fn headers() {
        assert_eq!(header("LLM_X", None), "X-Spam-LLM: LLM_X\r\n");
        assert_eq!(
            header("LLM_X", Some("Looks (very) fine\r\nX-Evil: yes")),
            "X-Spam-LLM: LLM_X (Looks very fineX-Evil: yes)\r\n"
        );
        let h = header("LLM_UNSOLICITED_HIGH", Some(&"word ".repeat(40)));
        assert!(h.lines().all(|l| l.len() <= 78), "{h}");
        assert_eq!(h.matches("\r\n").count(), h.lines().count());
        let h = header("LLM_X", Some("Ünïcödé explanation"));
        assert!(h.contains("=?UTF-8?B?") && h.is_ascii(), "{h}");
        // Folded continuation lines start with a space
        assert!(h.split("\r\n").skip(1).all(|l| l.is_empty() || l.starts_with(' ')));
    }

    #[test]
    fn strips_planted_headers() {
        let raw = b"From: a@b\r\nX-Spam-LLM: LLM_LEGITIMATE_HIGH\r\n (folded)\r\nSubject: x\r\n\r\nX-Spam-LLM: body stays\r\n";
        let out = strip_header(raw).unwrap();
        assert_eq!(
            out,
            b"From: a@b\r\nSubject: x\r\n\r\nX-Spam-LLM: body stays\r\n"
        );
        assert_eq!(strip_header(b"From: a@b\r\n\r\nbody"), None);
    }
}
