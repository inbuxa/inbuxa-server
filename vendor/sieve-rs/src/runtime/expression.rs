/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use std::{cmp::Ordering, fmt::Display};

use crate::Event;
use crate::compiler::grammar::expr::parser::ID_EXTERNAL;
use crate::{Context, compiler::Number, runtime::Variable};

use crate::compiler::grammar::expr::{BinaryOperator, Constant, Expression, UnaryOperator};

impl Context<'_> {
    pub(crate) fn eval_expression(&mut self, expr: &[Expression]) -> Result<Variable, Event> {
        let mut exprs = expr.iter().skip(self.expr_pos);
        while let Some(expr) = exprs.next() {
            self.expr_pos += 1;
            match expr {
                Expression::Variable(v) => {
                    self.expr_stack.push(self.variable(v).unwrap_or_default());
                }
                Expression::Constant(val) => {
                    self.expr_stack.push(Variable::from(val));
                }
                Expression::UnaryOperator(op) => {
                    let value = self.expr_stack.pop().unwrap_or_default();
                    self.expr_stack.push(match op {
                        UnaryOperator::Not => value.op_not(),
                        UnaryOperator::Minus => value.op_minus(),
                    });
                }
                Expression::BinaryOperator(op) => {
                    let right = self.expr_stack.pop().unwrap_or_default();
                    let left = self.expr_stack.pop().unwrap_or_default();
                    self.expr_stack.push(match op {
                        // inbuxa: no longer than a variable may be
                        BinaryOperator::Add => {
                            left.op_add_limited(right, self.runtime.max_variable_size)
                        }
                        BinaryOperator::Subtract => left.op_subtract(right),
                        BinaryOperator::Multiply => left.op_multiply(right),
                        BinaryOperator::Divide => left.op_divide(right),
                        BinaryOperator::And => left.op_and(right),
                        BinaryOperator::Or => left.op_or(right),
                        BinaryOperator::Xor => left.op_xor(right),
                        BinaryOperator::Eq => left.op_eq(right),
                        BinaryOperator::Ne => left.op_ne(right),
                        BinaryOperator::Lt => left.op_lt(right),
                        BinaryOperator::Le => left.op_le(right),
                        BinaryOperator::Gt => left.op_gt(right),
                        BinaryOperator::Ge => left.op_ge(right),
                    });
                }
                Expression::Function { id, num_args } => {
                    let num_args = *num_args as usize;

                    if let Some(fnc) = self.runtime.functions.get(*id as usize) {
                        let mut arguments = vec![Variable::Integer(0); num_args];
                        for arg_num in 0..num_args {
                            arguments[num_args - arg_num - 1] =
                                self.expr_stack.pop().unwrap_or_default();
                        }
                        self.expr_stack.push((fnc)(self, arguments));
                    } else {
                        let mut arguments = vec![Variable::Integer(0); num_args];
                        for arg_num in 0..num_args {
                            arguments[num_args - arg_num - 1] =
                                self.expr_stack.pop().unwrap_or_default();
                        }
                        self.pos -= 1; // We need to re-evaluate the function call
                        return Err(Event::Function {
                            id: ID_EXTERNAL - *id,
                            arguments,
                        });
                    }
                }
                Expression::JmpIf { val, pos } => {
                    if self.expr_stack.last().is_some_and(|v| v.to_bool()) == *val {
                        self.expr_pos += *pos as usize;
                        for _ in 0..*pos {
                            exprs.next();
                        }
                    }
                }
                Expression::ArrayAccess => {
                    let index = self.expr_stack.pop().unwrap_or_default().to_usize();
                    let array = self.expr_stack.pop().unwrap_or_default().into_array();
                    self.expr_stack
                        .push(array.get(index).cloned().unwrap_or_default());
                }
                Expression::ArrayBuild(num_items) => {
                    let num_items = *num_items as usize;
                    let mut items = vec![Variable::Integer(0); num_items];
                    for arg_num in 0..num_items {
                        items[num_items - arg_num - 1] = self.expr_stack.pop().unwrap_or_default();
                    }
                    self.expr_stack.push(Variable::Array(items.into()));
                }
            }
        }

        let result = self.expr_stack.pop().unwrap_or_default();
        self.expr_stack.clear();
        self.expr_pos = 0;
        Ok(result)
    }
}

impl Variable {
    pub fn op_add(self, other: Variable) -> Variable {
        self.op_add_limited(other, usize::MAX)
    }

    // inbuxa: a string or array that `+` builds holds at most `max_len`
    // bytes (as `len` counts them), cut at a character or an item. One
    // expression can add up thousands of terms, and upstream built each
    // whole sum before `let` truncated it.
    pub fn op_add_limited(self, other: Variable, max_len: usize) -> Variable {
        match (self, other) {
            (Variable::Integer(a), Variable::Integer(b)) => Variable::Integer(a.saturating_add(b)),
            (Variable::Float(a), Variable::Float(b)) => Variable::Float(a + b),
            (Variable::Integer(i), Variable::Float(f))
            | (Variable::Float(f), Variable::Integer(i)) => Variable::Float(i as f64 + f),
            (Variable::Array(a), Variable::Array(b)) => {
                limited_array(a.iter().chain(b.iter()).cloned(), max_len)
            }
            (Variable::Array(a), b) => limited_array(a.iter().cloned().chain([b]), max_len),
            (a, Variable::Array(b)) => {
                limited_array([a].into_iter().chain(b.iter().cloned()), max_len)
            }
            (Variable::String(a), b) => {
                if !a.is_empty() {
                    limited_string(&a, b.to_string().as_ref(), max_len)
                } else {
                    limited(b, max_len)
                }
            }
            (a, Variable::String(b)) => {
                if !b.is_empty() {
                    limited_string(a.to_string().as_ref(), &b, max_len)
                } else {
                    limited(a, max_len)
                }
            }
        }
    }

    pub fn op_subtract(self, other: Variable) -> Variable {
        match (self, other) {
            (Variable::Integer(a), Variable::Integer(b)) => Variable::Integer(a.saturating_sub(b)),
            (Variable::Float(a), Variable::Float(b)) => Variable::Float(a - b),
            (Variable::Integer(a), Variable::Float(b)) => Variable::Float(a as f64 - b),
            (Variable::Float(a), Variable::Integer(b)) => Variable::Float(a - b as f64),
            (Variable::Array(a), b) | (b, Variable::Array(a)) => Variable::Array(
                a.iter()
                    .filter(|v| *v != &b)
                    .cloned()
                    .collect::<Vec<_>>()
                    .into(),
            ),
            (a, b) => a.parse_number().op_subtract(b.parse_number()),
        }
    }

    pub fn op_multiply(self, other: Variable) -> Variable {
        match (self, other) {
            (Variable::Integer(a), Variable::Integer(b)) => Variable::Integer(a.saturating_mul(b)),
            (Variable::Float(a), Variable::Float(b)) => Variable::Float(a * b),
            (Variable::Integer(i), Variable::Float(f))
            | (Variable::Float(f), Variable::Integer(i)) => Variable::Float(i as f64 * f),
            (a, b) => a.parse_number().op_multiply(b.parse_number()),
        }
    }

    pub fn op_divide(self, other: Variable) -> Variable {
        match (self, other) {
            (Variable::Integer(a), Variable::Integer(b)) => {
                Variable::Float(if b != 0 { a as f64 / b as f64 } else { 0.0 })
            }
            (Variable::Float(a), Variable::Float(b)) => {
                Variable::Float(if b != 0.0 { a / b } else { 0.0 })
            }
            (Variable::Integer(a), Variable::Float(b)) => {
                Variable::Float(if b != 0.0 { a as f64 / b } else { 0.0 })
            }
            (Variable::Float(a), Variable::Integer(b)) => {
                Variable::Float(if b != 0 { a / b as f64 } else { 0.0 })
            }
            (a, b) => a.parse_number().op_divide(b.parse_number()),
        }
    }

    pub fn op_and(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self.to_bool() & other.to_bool()))
    }

    pub fn op_or(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self.to_bool() | other.to_bool()))
    }

    pub fn op_xor(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self.to_bool() ^ other.to_bool()))
    }

    pub fn op_eq(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self == other))
    }

    pub fn op_ne(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self != other))
    }

    pub fn op_lt(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self < other))
    }

    pub fn op_le(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self <= other))
    }

    pub fn op_gt(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self > other))
    }

    pub fn op_ge(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self >= other))
    }

    pub fn op_not(self) -> Variable {
        Variable::Integer(i64::from(!self.to_bool()))
    }

    pub fn op_minus(self) -> Variable {
        match self {
            Variable::Integer(n) => Variable::Integer(-n),
            Variable::Float(n) => Variable::Float(-n),
            _ => self.parse_number().op_minus(),
        }
    }

    pub fn parse_number(&self) -> Variable {
        match self {
            Variable::String(s) if !s.is_empty() => {
                if let Ok(n) = s.parse::<i64>() {
                    Variable::Integer(n)
                } else if let Ok(n) = s.parse::<f64>() {
                    Variable::Float(n)
                } else {
                    Variable::Integer(0)
                }
            }
            Variable::Integer(n) => Variable::Integer(*n),
            Variable::Float(n) => Variable::Float(*n),
            Variable::Array(l) => Variable::Integer(l.is_empty() as i64),
            _ => Variable::Integer(0),
        }
    }

    pub fn to_bool(&self) -> bool {
        match self {
            Variable::Float(f) => *f != 0.0,
            Variable::Integer(n) => *n != 0,
            Variable::String(s) => !s.is_empty(),
            Variable::Array(a) => !a.is_empty(),
        }
    }
}

impl PartialEq for Variable {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Integer(a), Self::Integer(b)) => a == b,
            (Self::Float(a), Self::Float(b)) => a == b,
            (Self::Integer(a), Self::Float(b)) | (Self::Float(b), Self::Integer(a)) => {
                *a as f64 == *b
            }
            (Self::String(a), Self::String(b)) => a == b,
            (Self::String(_), Self::Integer(_) | Self::Float(_)) => &self.parse_number() == other,
            (Self::Integer(_) | Self::Float(_), Self::String(_)) => self == &other.parse_number(),
            (Self::Array(a), Self::Array(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Variable {}

#[allow(clippy::non_canonical_partial_ord_impl)]
impl PartialOrd for Variable {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Self::Integer(a), Self::Integer(b)) => a.partial_cmp(b),
            (Self::Float(a), Self::Float(b)) => a.partial_cmp(b),
            (Self::Integer(a), Self::Float(b)) => (*a as f64).partial_cmp(b),
            (Self::Float(a), Self::Integer(b)) => a.partial_cmp(&(*b as f64)),
            (Self::String(a), Self::String(b)) => a.partial_cmp(b),
            (Self::String(_), Self::Integer(_) | Self::Float(_)) => {
                self.parse_number().partial_cmp(other)
            }
            (Self::Integer(_) | Self::Float(_), Self::String(_)) => {
                self.partial_cmp(&other.parse_number())
            }
            (Self::Array(a), Self::Array(b)) => a.partial_cmp(b),
            (Self::Array(_) | Self::String(_), _) => Ordering::Greater.into(),
            (_, Self::Array(_)) => Ordering::Less.into(),
        }
    }
}

impl Ord for Variable {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap_or(Ordering::Greater)
    }
}

impl Display for Variable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Variable::String(v) => v.fmt(f),
            Variable::Integer(v) => v.fmt(f),
            Variable::Float(v) => v.fmt(f),
            Variable::Array(v) => {
                for (i, v) in v.iter().enumerate() {
                    if i > 0 {
                        f.write_str("\n")?;
                    }
                    v.fmt(f)?;
                }
                Ok(())
            }
        }
    }
}

impl Number {
    pub fn is_non_zero(&self) -> bool {
        match self {
            Number::Integer(n) => *n != 0,
            Number::Float(n) => *n != 0.0,
        }
    }
}

impl Default for Number {
    fn default() -> Self {
        Number::Integer(0)
    }
}

impl From<bool> for Number {
    #[inline(always)]
    fn from(b: bool) -> Self {
        Number::Integer(i64::from(b))
    }
}

impl From<i64> for Number {
    #[inline(always)]
    fn from(n: i64) -> Self {
        Number::Integer(n)
    }
}

impl From<f64> for Number {
    #[inline(always)]
    fn from(n: f64) -> Self {
        Number::Float(n)
    }
}

impl From<i32> for Number {
    #[inline(always)]
    fn from(n: i32) -> Self {
        Number::Integer(n as i64)
    }
}

// inbuxa: `a` followed by `b`, cut to `max_len` bytes at a character
fn limited_string(a: &str, b: &str, max_len: usize) -> Variable {
    let mut result = String::with_capacity(a.len().saturating_add(b.len()).min(max_len));
    for part in [a, b] {
        let room = max_len - result.len();
        if part.len() <= room {
            result.push_str(part);
        } else {
            let mut end = room;
            while !part.is_char_boundary(end) {
                end -= 1;
            }
            result.push_str(&part[..end]);
            break;
        }
    }
    Variable::String(result.into())
}

// inbuxa: the items, up to the last one that fits in `max_len`
fn limited_array(items: impl Iterator<Item = Variable>, max_len: usize) -> Variable {
    let mut total = 0usize;
    let mut result = Vec::new();
    for item in items {
        total = total.saturating_add(item.len()).saturating_add(2);
        if total > max_len {
            break;
        }
        result.push(item);
    }
    Variable::Array(result.into())
}

// inbuxa: a value `+` passes on unchanged, cut like the ones it builds
fn limited(value: Variable, max_len: usize) -> Variable {
    match value {
        Variable::String(s) if s.len() > max_len => limited_string(&s, "", max_len),
        Variable::Array(a) if value_len(&a) > max_len => limited_array(a.iter().cloned(), max_len),
        value => value,
    }
}

fn value_len(items: &[Variable]) -> usize {
    items.iter().map(|v| v.len() + 2).sum()
}

impl<'x> From<&'x Constant> for Variable {
    fn from(value: &'x Constant) -> Self {
        match value {
            Constant::Integer(i) => Variable::Integer(*i),
            Constant::Float(f) => Variable::Float(*f),
            Constant::String(s) => Variable::String(s.clone()),
        }
    }
}

#[cfg(test)]
mod test {
    use ahash::{HashMap, HashMapExt};

    use crate::{
        compiler::{
            VariableType,
            grammar::expr::{
                BinaryOperator, Expression, Token, UnaryOperator, parser::ExpressionParser,
                tokenizer::Tokenizer,
            },
        },
        runtime::Variable,
    };

    use evalexpr::*;

    pub trait EvalExpression {
        fn eval(&self, variables: &HashMap<String, Variable>) -> Option<Variable>;
    }

    impl EvalExpression for Vec<Expression> {
        fn eval(&self, variables: &HashMap<String, Variable>) -> Option<Variable> {
            let mut stack = Vec::with_capacity(self.len());
            let mut exprs = self.iter();

            while let Some(expr) = exprs.next() {
                match expr {
                    Expression::Variable(VariableType::Global(v)) => {
                        stack.push(variables.get(v)?.clone());
                    }
                    Expression::Constant(val) => {
                        stack.push(Variable::from(val));
                    }
                    Expression::UnaryOperator(op) => {
                        let value = stack.pop()?;
                        stack.push(match op {
                            UnaryOperator::Not => value.op_not(),
                            UnaryOperator::Minus => value.op_minus(),
                        });
                    }
                    Expression::BinaryOperator(op) => {
                        let right = stack.pop()?;
                        let left = stack.pop()?;
                        stack.push(match op {
                            BinaryOperator::Add => left.op_add(right),
                            BinaryOperator::Subtract => left.op_subtract(right),
                            BinaryOperator::Multiply => left.op_multiply(right),
                            BinaryOperator::Divide => left.op_divide(right),
                            BinaryOperator::And => left.op_and(right),
                            BinaryOperator::Or => left.op_or(right),
                            BinaryOperator::Xor => left.op_xor(right),
                            BinaryOperator::Eq => left.op_eq(right),
                            BinaryOperator::Ne => left.op_ne(right),
                            BinaryOperator::Lt => left.op_lt(right),
                            BinaryOperator::Le => left.op_le(right),
                            BinaryOperator::Gt => left.op_gt(right),
                            BinaryOperator::Ge => left.op_ge(right),
                        });
                    }
                    Expression::JmpIf { val, pos } => {
                        if stack.last()?.to_bool() == *val {
                            for _ in 0..*pos {
                                exprs.next();
                            }
                        }
                    }
                    _ => unreachable!("Invalid expression"),
                }
            }
            stack.pop()
        }
    }

    #[test]
    fn eval_expression() {
        let mut variables = HashMap::from_iter([
            ("A".to_string(), Variable::Integer(0)),
            ("B".to_string(), Variable::Integer(0)),
            ("C".to_string(), Variable::Integer(0)),
            ("D".to_string(), Variable::Integer(0)),
            ("E".to_string(), Variable::Integer(0)),
            ("F".to_string(), Variable::Integer(0)),
            ("G".to_string(), Variable::Integer(0)),
            ("H".to_string(), Variable::Integer(0)),
            ("I".to_string(), Variable::Integer(0)),
            ("J".to_string(), Variable::Integer(0)),
        ]);
        let num_vars = variables.len();

        for expr in [
            "A + B",
            "A * B",
            "A / B",
            "A - B",
            "-A",
            "A == B",
            "A != B",
            "A > B",
            "A < B",
            "A >= B",
            "A <= B",
            "A + B * C - D / E",
            "A + B + C - D - E",
            "(A + B) * (C - D) / E",
            "A - B + C * D / E * F - G",
            "A + B * C - D / E",
            "(A + B) * (C - D) / E",
            "A - B + C / D * E",
            "(A + B) / (C - D) + E",
            "A * (B + C) - D / E",
            "A / (B - C + D) * E",
            "(A + B) * C - D / (E + F)",
            "A * B - C + D / E",
            "A + B - C * D / E",
            "(A * B + C) / D - E",
            "A - B / C + D * E",
            "A + B * (C - D) / E",
            "A * B / C + (D - E)",
            "(A - B) * C / D + E",
            "A * (B / C) - D + E",
            "(A + B) / (C + D) * E",
            "A - B * C / D + E",
            "A + (B - C) * D / E",
            "(A + B) * (C / D) - E",
            "A - B / (C * D) + E",
            "(A + B) > (C - D) && E <= F",
            "A * B == C / D || E - F != G + H",
            "A / B >= C * D && E + F < G - H",
            "(A * B - C) != (D / E + F) && G > H",
            "A - B < C && D + E >= F * G",
            "(A * B) > C && (D / E) < F || G == H",
            "(A + B) <= (C - D) || E > F && G != H",
            "A * B != C + D || E - F == G / H",
            "A >= B * C && D < E - F || G != H + I",
            "(A / B + C) > D && E * F <= G - H",
            "A * (B - C) == D && E / F > G + H",
            "(A - B + C) != D || E * F >= G && H < I",
            "A < B / C && D + E * F == G - H",
            "(A + B * C) <= D && E > F / G",
            "(A * B - C) > D || E <= F + G && H != I",
            "A != B / C && D == E * F - G",
            "A <= B + C - D && E / F > G * H",
            "(A - B * C) < D || E >= F + G && H != I",
            "(A + B) / C == D && E - F < G * H",
            "A * B != C && D >= E + F / G || H < I",
            "!(A * B != C) && !(D >= E + F / G) || !(H < I)",
            "-A - B - (- C - D) - E - (-F)",
        ] {
            println!("Testing {}", expr);
            for (pos, v) in variables.values_mut().enumerate() {
                *v = Variable::Integer(pos as i64 + 1);
            }

            assert_expr(expr, &variables);

            for (pos, v) in variables.values_mut().enumerate() {
                *v = Variable::Integer((num_vars - pos) as i64);
            }

            assert_expr(expr, &variables);
        }

        for expr in [
            "true && false",
            "!true || false",
            "true && !false",
            "!(true && false)",
            "true || true && false",
            "!false && (true || false)",
            "!(true || !false) && true",
            "!(!true && !false)",
            "true || false && !true",
            "!(true && true) || !false",
            "!(!true || !false) && (!false) && !(!true)",
        ] {
            let pexp = parse_expression(expr.replace("true", "1").replace("false", "0").as_str());
            let result = pexp.eval(&HashMap::new()).unwrap();

            //println!("{} => {:?}", expr, result);

            match (eval(expr).expect(expr), result) {
                (Value::Float(a), Variable::Float(b)) if a == b => (),
                (Value::Float(a), Variable::Integer(b)) if a == b as f64 => (),
                (Value::Boolean(a), Variable::Integer(b)) if a == (b != 0) => (),
                (a, b) => {
                    panic!("{} => {:?} != {:?}", expr, a, b)
                }
            }
        }
    }

    fn assert_expr(expr: &str, variables: &HashMap<String, Variable>) {
        let e = parse_expression(expr);

        let result = e.eval(variables).unwrap();

        let mut str_expr = expr.to_string();
        let mut str_expr_float = expr.to_string();
        for (k, v) in variables {
            let v = v.to_string();

            if v.contains('.') {
                str_expr_float = str_expr_float.replace(k, &v);
            } else {
                str_expr_float = str_expr_float.replace(k, &format!("{}.0", v));
            }
            str_expr = str_expr.replace(k, &v);
        }

        assert_eq!(
            parse_expression(&str_expr)
                .eval(&HashMap::new())
                .unwrap()
                .to_number()
                .to_float(),
            result.to_number().to_float()
        );

        assert_eq!(
            parse_expression(&str_expr_float)
                .eval(&HashMap::new())
                .unwrap()
                .to_number()
                .to_float(),
            result.to_number().to_float()
        );

        //println!("{str_expr} ({e:?}) => {result:?}");

        match (
            eval(&str_expr_float)
                .map(|v| {
                    // Divisions by zero are converted to 0.0
                    if matches!(&v, Value::Float(f) if f64::is_infinite(*f)) {
                        Value::Float(0.0)
                    } else {
                        v
                    }
                })
                .expect(&str_expr),
            result,
        ) {
            (Value::Float(a), Variable::Float(b)) if a == b => (),
            (Value::Float(a), Variable::Integer(b)) if a == b as f64 => (),
            (Value::Boolean(a), Variable::Integer(b)) if a == (b != 0) => (),
            (a, b) => {
                panic!("{} => {:?} != {:?}", str_expr, a, b)
            }
        }
    }

    fn parse_expression(expr: &str) -> Vec<Expression> {
        ExpressionParser::from_tokenizer(Tokenizer::new(expr, |var_name: &str, _: bool| {
            Ok::<_, String>(Token::Variable(VariableType::Global(var_name.to_string())))
        }))
        .parse()
        .unwrap()
        .output
    }
}

// inbuxa: `+` builds strings and arrays no longer than the runtime's
// max_variable_size, however many terms one expression adds up
#[cfg(test)]
mod concat_limit_tests {
    use mail_parser::MessageParser;

    use crate::{
        Context, Runtime,
        compiler::{
            VariableType,
            grammar::expr::{Token, parser::ExpressionParser, tokenizer::Tokenizer},
        },
        runtime::Variable,
    };

    const MAX: usize = 64;

    fn eval(expr: &str, value: Variable) -> Variable {
        let runtime = Runtime::new().with_max_variable_size(MAX);
        let mut ctx = Context::new(
            &runtime,
            MessageParser::new()
                .parse(b"From: a@example.org\r\n\r\nhi\r\n")
                .unwrap(),
        );
        ctx.vars_global.insert("x".into(), value);
        let expr = ExpressionParser::from_tokenizer(Tokenizer::new(expr, |name: &str, _: bool| {
            Ok::<_, String>(Token::Variable(VariableType::Global(name.to_string())))
        }))
        .parse()
        .unwrap()
        .output;
        ctx.eval_expression(&expr).unwrap()
    }

    fn terms(term: &str, n: usize) -> String {
        vec![term; n].join(" + ")
    }

    #[test]
    fn concatenation_is_capped_at_max_variable_size() {
        let full = Variable::from("é".repeat(MAX / 2));

        let result = eval(&terms("x", 50), full.clone());
        assert!(
            result.len() <= MAX,
            "50 strings of {MAX} bytes made {} bytes",
            result.len()
        );
        // the cut keeps whole characters, and as much as fits
        assert_eq!(result.to_string().as_ref(), "é".repeat(MAX / 2));
        assert_eq!(eval("x + 'b'", Variable::from("a")).to_string(), "ab");
        assert_eq!(eval("x + 1", Variable::from("a")).to_string(), "a1");

        let result = eval(&terms("[x, x]", 50), full.clone());
        assert!(
            result.len() <= MAX,
            "50 arrays of two {MAX}-byte strings made {} bytes",
            result.len()
        );
        let result = eval(&terms("x", 50), Variable::Array(vec![full.clone()].into()));
        assert!(
            result.len() <= MAX,
            "an array grown 50 times made {} bytes",
            result.len()
        );
        let result = eval(&format!("'a' + {}", terms("[x]", 50)), full);
        assert!(
            result.len() <= MAX,
            "a string joined to 50 arrays made {} bytes",
            result.len()
        );

        // short values add up as before
        let result = eval("[x] + [x] + x", Variable::from("a"));
        assert_eq!(result.as_array().map(|a| a.len()), Some(3));
        assert_eq!(eval("x + x", Variable::Integer(2)), Variable::Integer(4));
    }
}
