use std::collections::BTreeMap;
use tessera_core::{State, TesseraError, Value};

/// Evaluate a simple expression against the current state and mutation arguments.
///
/// Supported expressions:
/// - Field references: `field_name` -> looks up in state, then args
/// - Integer literals: `42`, `-5`
/// - Boolean literals: `true`, `false`
/// - String literals: `"hello"`
/// - Arithmetic: `a + b`, `a - b`, `a * b`, `a / b`, `a % b`
/// - Comparisons: `a < b`, `a > b`, `a <= b`, `a >= b`, `a == b`, `a != b`
/// - Boolean ops: `a && b`, `a || b`, `!a`
pub fn evaluate_expr(
    expr: &str,
    state: &State,
    args: &BTreeMap<String, Value>,
) -> Result<Value, TesseraError> {
    let tokens = tokenize(expr)?;
    let mut parser = Parser::new(&tokens, state, args);
    parser.parse_expr()
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    IntLit(i64),
    BoolLit(bool),
    StringLit(String),
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Lt,
    Gt,
    LtEq,
    GtEq,
    EqEq,
    BangEq,
    And,
    Or,
    Bang,
    LParen,
    RParen,
}

fn tokenize(input: &str) -> Result<Vec<Token>, TesseraError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            ' ' | '\t' | '\n' | '\r' => i += 1,
            '+' => {
                tokens.push(Token::Plus);
                i += 1;
            }
            '-' if i + 1 < chars.len()
                && chars[i + 1].is_ascii_digit()
                && (tokens.is_empty()
                    || matches!(
                        tokens.last(),
                        Some(
                            Token::LParen
                                | Token::Plus
                                | Token::Minus
                                | Token::Star
                                | Token::Slash
                                | Token::Percent
                                | Token::Lt
                                | Token::Gt
                                | Token::LtEq
                                | Token::GtEq
                                | Token::EqEq
                                | Token::BangEq
                                | Token::And
                                | Token::Or
                                | Token::Bang
                        )
                    )) =>
            {
                // Negative number literal
                let start = i;
                i += 1;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                let num: i64 = input[start..i]
                    .parse()
                    .map_err(|e| TesseraError::SchemaViolation(format!("invalid number: {}", e)))?;
                tokens.push(Token::IntLit(num));
            }
            '-' => {
                tokens.push(Token::Minus);
                i += 1;
            }
            '*' => {
                tokens.push(Token::Star);
                i += 1;
            }
            '/' => {
                tokens.push(Token::Slash);
                i += 1;
            }
            '%' => {
                tokens.push(Token::Percent);
                i += 1;
            }
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            '<' if i + 1 < chars.len() && chars[i + 1] == '=' => {
                tokens.push(Token::LtEq);
                i += 2;
            }
            '<' => {
                tokens.push(Token::Lt);
                i += 1;
            }
            '>' if i + 1 < chars.len() && chars[i + 1] == '=' => {
                tokens.push(Token::GtEq);
                i += 2;
            }
            '>' => {
                tokens.push(Token::Gt);
                i += 1;
            }
            '=' if i + 1 < chars.len() && chars[i + 1] == '=' => {
                tokens.push(Token::EqEq);
                i += 2;
            }
            '!' if i + 1 < chars.len() && chars[i + 1] == '=' => {
                tokens.push(Token::BangEq);
                i += 2;
            }
            '!' => {
                tokens.push(Token::Bang);
                i += 1;
            }
            '&' if i + 1 < chars.len() && chars[i + 1] == '&' => {
                tokens.push(Token::And);
                i += 2;
            }
            '|' if i + 1 < chars.len() && chars[i + 1] == '|' => {
                tokens.push(Token::Or);
                i += 2;
            }
            '"' => {
                i += 1;
                let mut s = String::new();
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        i += 1;
                        match chars[i] {
                            '"' => s.push('"'),
                            '\\' => s.push('\\'),
                            'n' => s.push('\n'),
                            't' => s.push('\t'),
                            'r' => s.push('\r'),
                            c => {
                                return Err(TesseraError::SchemaViolation(format!(
                                    "unknown escape sequence: \\{}",
                                    c
                                )));
                            }
                        }
                    } else {
                        s.push(chars[i]);
                    }
                    i += 1;
                }
                if i >= chars.len() {
                    return Err(TesseraError::SchemaViolation("unterminated string".into()));
                }
                tokens.push(Token::StringLit(s));
                i += 1; // skip closing quote
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                let num: i64 = input[start..i]
                    .parse()
                    .map_err(|e| TesseraError::SchemaViolation(format!("invalid number: {}", e)))?;
                tokens.push(Token::IntLit(num));
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                match word.as_str() {
                    "true" => tokens.push(Token::BoolLit(true)),
                    "false" => tokens.push(Token::BoolLit(false)),
                    _ => tokens.push(Token::Ident(word)),
                }
            }
            c => {
                return Err(TesseraError::SchemaViolation(format!(
                    "unexpected character: '{}'",
                    c
                )));
            }
        }
    }

    Ok(tokens)
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
    state: &'a State,
    args: &'a BTreeMap<String, Value>,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token], state: &'a State, args: &'a BTreeMap<String, Value>) -> Self {
        Self {
            tokens,
            pos: 0,
            state,
            args,
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<&Token> {
        let tok = self.tokens.get(self.pos);
        self.pos += 1;
        tok
    }

    /// Parse: or_expr
    fn parse_expr(&mut self) -> Result<Value, TesseraError> {
        self.parse_or()
    }

    /// or_expr: and_expr (|| and_expr)*
    fn parse_or(&mut self) -> Result<Value, TesseraError> {
        let mut left = self.parse_and()?;
        while self.peek() == Some(&Token::Or) {
            self.advance();
            let right = self.parse_and()?;
            left = match (&left, &right) {
                (Value::Bool(a), Value::Bool(b)) => Value::Bool(*a || *b),
                _ => {
                    return Err(TesseraError::SchemaViolation(
                        "|| requires bool operands".into(),
                    ))
                }
            };
        }
        Ok(left)
    }

    /// and_expr: comparison (&&  comparison)*
    fn parse_and(&mut self) -> Result<Value, TesseraError> {
        let mut left = self.parse_comparison()?;
        while self.peek() == Some(&Token::And) {
            self.advance();
            let right = self.parse_comparison()?;
            left = match (&left, &right) {
                (Value::Bool(a), Value::Bool(b)) => Value::Bool(*a && *b),
                _ => {
                    return Err(TesseraError::SchemaViolation(
                        "&& requires bool operands".into(),
                    ))
                }
            };
        }
        Ok(left)
    }

    /// comparison: additive ((<|>|<=|>=|==|!=) additive)?
    fn parse_comparison(&mut self) -> Result<Value, TesseraError> {
        let left = self.parse_additive()?;

        match self.peek() {
            Some(Token::Lt) | Some(Token::Gt) | Some(Token::LtEq) | Some(Token::GtEq)
            | Some(Token::EqEq) | Some(Token::BangEq) => {
                let op = self.advance().unwrap().clone();
                let right = self.parse_additive()?;
                compare_values(&left, &right, &op)
            }
            _ => Ok(left),
        }
    }

    /// additive: multiplicative ((+|-) multiplicative)*
    fn parse_additive(&mut self) -> Result<Value, TesseraError> {
        let mut left = self.parse_multiplicative()?;
        loop {
            match self.peek() {
                Some(Token::Plus) => {
                    self.advance();
                    let right = self.parse_multiplicative()?;
                    left = arith_op(&left, &right, "+")?;
                }
                Some(Token::Minus) => {
                    self.advance();
                    let right = self.parse_multiplicative()?;
                    left = arith_op(&left, &right, "-")?;
                }
                _ => break,
            }
        }
        Ok(left)
    }

    /// multiplicative: unary ((*|/|%) unary)*
    fn parse_multiplicative(&mut self) -> Result<Value, TesseraError> {
        let mut left = self.parse_unary()?;
        loop {
            match self.peek() {
                Some(Token::Star) => {
                    self.advance();
                    let right = self.parse_unary()?;
                    left = arith_op(&left, &right, "*")?;
                }
                Some(Token::Slash) => {
                    self.advance();
                    let right = self.parse_unary()?;
                    left = arith_op(&left, &right, "/")?;
                }
                Some(Token::Percent) => {
                    self.advance();
                    let right = self.parse_unary()?;
                    left = arith_op(&left, &right, "%")?;
                }
                _ => break,
            }
        }
        Ok(left)
    }

    /// unary: !unary | primary
    fn parse_unary(&mut self) -> Result<Value, TesseraError> {
        if self.peek() == Some(&Token::Bang) {
            self.advance();
            let val = self.parse_unary()?;
            match val {
                Value::Bool(b) => Ok(Value::Bool(!b)),
                _ => Err(TesseraError::SchemaViolation("! requires bool".into())),
            }
        } else {
            self.parse_primary()
        }
    }

    /// primary: int_lit | bool_lit | string_lit | ident | (expr)
    fn parse_primary(&mut self) -> Result<Value, TesseraError> {
        match self.advance() {
            Some(Token::IntLit(n)) => {
                let n = *n;
                if n >= 0 {
                    Ok(Value::U64(n as u64))
                } else {
                    Ok(Value::I64(n))
                }
            }
            Some(Token::BoolLit(b)) => Ok(Value::Bool(*b)),
            Some(Token::StringLit(s)) => Ok(Value::String(s.clone())),
            Some(Token::Ident(name)) => {
                let name = name.clone();
                // Look up in args first, then state
                if let Some(val) = self.args.get(&name) {
                    Ok(val.clone())
                } else if let Some(val) = self.state.get(&name) {
                    Ok(val.clone())
                } else {
                    Err(TesseraError::UnknownField(name))
                }
            }
            Some(Token::LParen) => {
                let val = self.parse_expr()?;
                match self.advance() {
                    Some(Token::RParen) => Ok(val),
                    _ => Err(TesseraError::SchemaViolation("expected closing ')'".into())),
                }
            }
            Some(tok) => Err(TesseraError::SchemaViolation(format!(
                "unexpected token: {:?}",
                tok
            ))),
            None => Err(TesseraError::SchemaViolation(
                "unexpected end of expression".into(),
            )),
        }
    }
}

fn to_i64(v: &Value) -> Result<i64, TesseraError> {
    match v {
        Value::U64(n) => i64::try_from(*n)
            .map_err(|_| TesseraError::SchemaViolation("u64 too large for arithmetic".into())),
        Value::I64(n) => Ok(*n),
        _ => Err(TesseraError::SchemaViolation(format!(
            "expected numeric, got {}",
            v.type_name()
        ))),
    }
}

fn from_i64(n: i64) -> Value {
    if n >= 0 {
        Value::U64(n as u64)
    } else {
        Value::I64(n)
    }
}

fn arith_op(left: &Value, right: &Value, op: &str) -> Result<Value, TesseraError> {
    let a = to_i64(left)?;
    let b = to_i64(right)?;

    let result = match op {
        "+" => a.checked_add(b),
        "-" => a.checked_sub(b),
        "*" => a.checked_mul(b),
        "/" => {
            if b == 0 {
                return Err(TesseraError::SchemaViolation("division by zero".into()));
            }
            a.checked_div(b)
        }
        "%" => {
            if b == 0 {
                return Err(TesseraError::SchemaViolation("modulo by zero".into()));
            }
            a.checked_rem(b)
        }
        _ => unreachable!(),
    };

    result.map(from_i64).ok_or_else(|| {
        TesseraError::SchemaViolation(format!("arithmetic overflow: {} {} {}", a, op, b))
    })
}

fn compare_values(left: &Value, right: &Value, op: &Token) -> Result<Value, TesseraError> {
    // Numeric comparison
    if let (Ok(a), Ok(b)) = (to_i64(left), to_i64(right)) {
        return Ok(Value::Bool(match op {
            Token::Lt => a < b,
            Token::Gt => a > b,
            Token::LtEq => a <= b,
            Token::GtEq => a >= b,
            Token::EqEq => a == b,
            Token::BangEq => a != b,
            _ => unreachable!(),
        }));
    }

    // String comparison
    if let (Value::String(a), Value::String(b)) = (left, right) {
        return Ok(Value::Bool(match op {
            Token::EqEq => a == b,
            Token::BangEq => a != b,
            Token::Lt => a < b,
            Token::Gt => a > b,
            Token::LtEq => a <= b,
            Token::GtEq => a >= b,
            _ => unreachable!(),
        }));
    }

    // Bool equality
    if let (Value::Bool(a), Value::Bool(b)) = (left, right) {
        return Ok(Value::Bool(match op {
            Token::EqEq => a == b,
            Token::BangEq => a != b,
            _ => {
                return Err(TesseraError::SchemaViolation(
                    "booleans only support == and !=".into(),
                ))
            }
        }));
    }

    Err(TesseraError::SchemaViolation(format!(
        "cannot compare {} and {}",
        left.type_name(),
        right.type_name()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_state() -> State {
        BTreeMap::new()
    }

    fn empty_args() -> BTreeMap<String, Value> {
        BTreeMap::new()
    }

    fn state_with(pairs: Vec<(&str, Value)>) -> State {
        let mut s = BTreeMap::new();
        for (k, v) in pairs {
            s.insert(k.into(), v);
        }
        s
    }

    #[test]
    fn integer_literal() {
        let v = evaluate_expr("42", &empty_state(), &empty_args()).unwrap();
        assert_eq!(v, Value::U64(42));
    }

    #[test]
    fn negative_integer() {
        let v = evaluate_expr("-5", &empty_state(), &empty_args()).unwrap();
        assert_eq!(v, Value::I64(-5));
    }

    #[test]
    fn bool_literal() {
        assert_eq!(
            evaluate_expr("true", &empty_state(), &empty_args()).unwrap(),
            Value::Bool(true)
        );
        assert_eq!(
            evaluate_expr("false", &empty_state(), &empty_args()).unwrap(),
            Value::Bool(false)
        );
    }

    #[test]
    fn string_literal() {
        let v = evaluate_expr("\"hello\"", &empty_state(), &empty_args()).unwrap();
        assert_eq!(v, Value::String("hello".into()));
    }

    #[test]
    fn field_reference() {
        let state = state_with(vec![("count", Value::U64(10))]);
        let v = evaluate_expr("count", &state, &empty_args()).unwrap();
        assert_eq!(v, Value::U64(10));
    }

    #[test]
    fn args_override_state() {
        let state = state_with(vec![("x", Value::U64(1))]);
        let mut args = BTreeMap::new();
        args.insert("x".into(), Value::U64(99));
        let v = evaluate_expr("x", &state, &args).unwrap();
        assert_eq!(v, Value::U64(99));
    }

    #[test]
    fn addition() {
        let state = state_with(vec![("count", Value::U64(5))]);
        let v = evaluate_expr("count + 1", &state, &empty_args()).unwrap();
        assert_eq!(v, Value::U64(6));
    }

    #[test]
    fn subtraction() {
        let state = state_with(vec![("count", Value::U64(5))]);
        let v = evaluate_expr("count - 1", &state, &empty_args()).unwrap();
        assert_eq!(v, Value::U64(4));
    }

    #[test]
    fn multiplication() {
        let v = evaluate_expr("3 * 4", &empty_state(), &empty_args()).unwrap();
        assert_eq!(v, Value::U64(12));
    }

    #[test]
    fn division() {
        let v = evaluate_expr("10 / 3", &empty_state(), &empty_args()).unwrap();
        assert_eq!(v, Value::U64(3));
    }

    #[test]
    fn modulo() {
        let v = evaluate_expr("10 % 3", &empty_state(), &empty_args()).unwrap();
        assert_eq!(v, Value::U64(1));
    }

    #[test]
    fn division_by_zero() {
        let r = evaluate_expr("10 / 0", &empty_state(), &empty_args());
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("division by zero"));
    }

    #[test]
    fn comparison_less_than() {
        let state = state_with(vec![("count", Value::U64(5))]);
        assert_eq!(
            evaluate_expr("count < 10", &state, &empty_args()).unwrap(),
            Value::Bool(true)
        );
        assert_eq!(
            evaluate_expr("count < 3", &state, &empty_args()).unwrap(),
            Value::Bool(false)
        );
    }

    #[test]
    fn comparison_greater_than() {
        let state = state_with(vec![("count", Value::U64(5))]);
        assert_eq!(
            evaluate_expr("count > 0", &state, &empty_args()).unwrap(),
            Value::Bool(true)
        );
        assert_eq!(
            evaluate_expr("count > 10", &state, &empty_args()).unwrap(),
            Value::Bool(false)
        );
    }

    #[test]
    fn comparison_equality() {
        let state = state_with(vec![("count", Value::U64(5))]);
        assert_eq!(
            evaluate_expr("count == 5", &state, &empty_args()).unwrap(),
            Value::Bool(true)
        );
        assert_eq!(
            evaluate_expr("count != 5", &state, &empty_args()).unwrap(),
            Value::Bool(false)
        );
    }

    #[test]
    fn boolean_and() {
        assert_eq!(
            evaluate_expr("true && true", &empty_state(), &empty_args()).unwrap(),
            Value::Bool(true)
        );
        assert_eq!(
            evaluate_expr("true && false", &empty_state(), &empty_args()).unwrap(),
            Value::Bool(false)
        );
    }

    #[test]
    fn boolean_or() {
        assert_eq!(
            evaluate_expr("false || true", &empty_state(), &empty_args()).unwrap(),
            Value::Bool(true)
        );
        assert_eq!(
            evaluate_expr("false || false", &empty_state(), &empty_args()).unwrap(),
            Value::Bool(false)
        );
    }

    #[test]
    fn boolean_not() {
        assert_eq!(
            evaluate_expr("!true", &empty_state(), &empty_args()).unwrap(),
            Value::Bool(false)
        );
        assert_eq!(
            evaluate_expr("!false", &empty_state(), &empty_args()).unwrap(),
            Value::Bool(true)
        );
    }

    #[test]
    fn parenthesized_expression() {
        let v = evaluate_expr("(3 + 4) * 2", &empty_state(), &empty_args()).unwrap();
        assert_eq!(v, Value::U64(14));
    }

    #[test]
    fn operator_precedence() {
        // * before +
        let v = evaluate_expr("3 + 4 * 2", &empty_state(), &empty_args()).unwrap();
        assert_eq!(v, Value::U64(11));
    }

    #[test]
    fn complex_guard_expression() {
        let state = state_with(vec![("count", Value::U64(5))]);
        let v = evaluate_expr("count >= 0 && count < 100", &state, &empty_args()).unwrap();
        assert_eq!(v, Value::Bool(true));
    }

    #[test]
    fn unknown_field_error() {
        let r = evaluate_expr("nonexistent", &empty_state(), &empty_args());
        assert!(r.is_err());
    }

    #[test]
    fn string_escape_quotes() {
        let v = evaluate_expr(r#""say \"hello\"""#, &empty_state(), &empty_args()).unwrap();
        assert_eq!(v, Value::String("say \"hello\"".into()));
    }

    #[test]
    fn string_escape_backslash() {
        let v = evaluate_expr(r#""a\\b""#, &empty_state(), &empty_args()).unwrap();
        assert_eq!(v, Value::String("a\\b".into()));
    }

    #[test]
    fn string_escape_newline_tab() {
        let v = evaluate_expr(r#""line1\nline2\tend""#, &empty_state(), &empty_args()).unwrap();
        assert_eq!(v, Value::String("line1\nline2\tend".into()));
    }

    #[test]
    fn string_unknown_escape_rejected() {
        let r = evaluate_expr(r#""bad\x""#, &empty_state(), &empty_args());
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("unknown escape"));
    }
}
