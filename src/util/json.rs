//! A small, dependency-free JSON implementation.
//!
//! Used for the on-disk container state store, the `--json` CLI output and
//! the JSON form of the container configuration file.  Objects preserve
//! insertion order (they are `Vec<(String, Json)>`) so that `state.json`
//! diffs cleanly and is pleasant to read by hand while debugging.

use crate::error::{Error, Result};
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn obj() -> Json {
        Json::Obj(Vec::new())
    }

    pub fn set<S: Into<String>>(&mut self, k: S, v: Json) -> &mut Json {
        if let Json::Obj(m) = self {
            let k = k.into();
            if let Some(slot) = m.iter_mut().find(|(ek, _)| *ek == k) {
                slot.1 = v;
            } else {
                m.push((k, v));
            }
        }
        self
    }

    pub fn get(&self, k: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.iter().find(|(ek, _)| ek == k).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn get_mut(&mut self, k: &str) -> Option<&mut Json> {
        match self {
            Json::Obj(m) => m.iter_mut().find(|(ek, _)| ek == k).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(i) => Some(*i),
            Json::Float(f) => Some(*f as i64),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Int(i) if *i >= 0 => Some(*i as u64),
            Json::Float(f) if *f >= 0.0 => Some(*f as u64),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Int(i) => Some(*i as f64),
            Json::Float(f) => Some(*f),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Obj(m) => Some(m),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }

    /// Convenience for building `Json::Arr` out of strings.
    pub fn strings<I: IntoIterator<Item = S>, S: Into<String>>(it: I) -> Json {
        Json::Arr(it.into_iter().map(|s| Json::Str(s.into())).collect())
    }

    pub fn to_string(&self) -> String {
        let mut s = String::new();
        self.write(&mut s, None, 0);
        s
    }

    pub fn to_string_pretty(&self) -> String {
        let mut s = String::new();
        self.write(&mut s, Some(2), 0);
        s
    }

    fn write(&self, out: &mut String, indent: Option<usize>, depth: usize) {
        let nl = |out: &mut String, depth: usize| {
            if let Some(step) = indent {
                out.push('\n');
                for _ in 0..(step * depth) {
                    out.push(' ');
                }
            }
        };
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Int(i) => {
                let _ = write!(out, "{}", i);
            }
            Json::Float(f) => {
                if f.is_finite() {
                    let _ = write!(out, "{}", f);
                } else {
                    out.push_str("null");
                }
            }
            Json::Str(s) => escape_into(s, out),
            Json::Arr(a) => {
                if a.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    nl(out, depth + 1);
                    v.write(out, indent, depth + 1);
                }
                nl(out, depth);
                out.push(']');
            }
            Json::Obj(m) => {
                if m.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    nl(out, depth + 1);
                    escape_into(k, out);
                    out.push(':');
                    if indent.is_some() {
                        out.push(' ');
                    }
                    v.write(out, indent, depth + 1);
                }
                nl(out, depth);
                out.push('}');
            }
        }
    }
}

fn escape_into(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

pub fn parse(input: &str) -> Result<Json> {
    let b = input.as_bytes();
    let mut p = Parser { b, i: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != b.len() {
        return Err(Error::parse(format!(
            "trailing data at byte offset {}",
            p.i
        )));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn err<T>(&self, msg: &str) -> Result<T> {
        Err(Error::parse(format!("{} at byte offset {}", msg, self.i)))
    }

    fn lit(&mut self, s: &str) -> bool {
        if self.b[self.i..].starts_with(s.as_bytes()) {
            self.i += s.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self) -> Result<Json> {
        match self.peek() {
            None => self.err("unexpected end of input"),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => {
                if self.lit("true") {
                    Ok(Json::Bool(true))
                } else {
                    self.err("invalid token")
                }
            }
            Some(b'f') => {
                if self.lit("false") {
                    Ok(Json::Bool(false))
                } else {
                    self.err("invalid token")
                }
            }
            Some(b'n') => {
                if self.lit("null") {
                    Ok(Json::Null)
                } else {
                    self.err("invalid token")
                }
            }
            Some(_) => self.number(),
        }
    }

    fn object(&mut self) -> Result<Json> {
        self.i += 1; // {
        let mut m = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Json::Obj(m));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return self.err("expected object key");
            }
            let k = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return self.err("expected ':'");
            }
            self.i += 1;
            self.ws();
            let v = self.value()?;
            m.push((k, v));
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Json::Obj(m));
                }
                _ => return self.err("expected ',' or '}'"),
            }
        }
    }

    fn array(&mut self) -> Result<Json> {
        self.i += 1; // [
        let mut a = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Json::Arr(a));
        }
        loop {
            self.ws();
            a.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    return Ok(Json::Arr(a));
                }
                _ => return self.err("expected ',' or ']'"),
            }
        }
    }

    fn string(&mut self) -> Result<String> {
        self.i += 1; // opening quote
        let mut s = String::new();
        loop {
            let c = match self.peek() {
                None => return self.err("unterminated string"),
                Some(c) => c,
            };
            self.i += 1;
            match c {
                b'"' => return Ok(s),
                b'\\' => {
                    let e = match self.peek() {
                        None => return self.err("unterminated escape"),
                        Some(e) => e,
                    };
                    self.i += 1;
                    match e {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        b'b' => s.push('\u{08}'),
                        b'f' => s.push('\u{0c}'),
                        b'u' => {
                            if self.i + 4 > self.b.len() {
                                return self.err("truncated \\u escape");
                            }
                            let hex = std::str::from_utf8(&self.b[self.i..self.i + 4])
                                .map_err(|_| Error::parse("bad \\u escape"))?;
                            let cp = u32::from_str_radix(hex, 16)
                                .map_err(|_| Error::parse("bad \\u escape"))?;
                            self.i += 4;
                            s.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                        }
                        _ => return self.err("unknown escape"),
                    }
                }
                c if c < 0x20 => return self.err("control character in string"),
                c if c < 0x80 => s.push(c as char),
                _ => {
                    // Multi-byte UTF-8: find the end of the sequence and copy.
                    let start = self.i - 1;
                    let len = if c >= 0xf0 {
                        4
                    } else if c >= 0xe0 {
                        3
                    } else {
                        2
                    };
                    if start + len > self.b.len() {
                        return self.err("truncated utf-8 sequence");
                    }
                    let chunk = std::str::from_utf8(&self.b[start..start + len])
                        .map_err(|_| Error::parse("invalid utf-8 in string"))?;
                    s.push_str(chunk);
                    self.i = start + len;
                }
            }
        }
    }

    fn number(&mut self) -> Result<Json> {
        let start = self.i;
        if self.peek() == Some(b'-') || self.peek() == Some(b'+') {
            self.i += 1;
        }
        let mut float = false;
        while let Some(c) = self.peek() {
            match c {
                b'0'..=b'9' => self.i += 1,
                b'.' | b'e' | b'E' | b'-' | b'+' => {
                    float = true;
                    self.i += 1;
                }
                _ => break,
            }
        }
        if start == self.i {
            return self.err("expected a value");
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).unwrap_or("");
        if float {
            text.parse::<f64>()
                .map(Json::Float)
                .map_err(|e| Error::parse(format!("bad number {:?}: {}", text, e)))
        } else {
            match text.parse::<i64>() {
                Ok(i) => Ok(Json::Int(i)),
                Err(_) => text
                    .parse::<f64>()
                    .map(Json::Float)
                    .map_err(|e| Error::parse(format!("bad number {:?}: {}", text, e))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_object() {
        let src = r#"{"a":1,"b":[true,null,"x"],"c":{"d":-2.5}}"#;
        let v = parse(src).unwrap();
        assert_eq!(v.get("a").unwrap().as_i64(), Some(1));
        assert_eq!(v.get("b").unwrap().as_array().unwrap().len(), 3);
        assert_eq!(
            v.get("c").unwrap().get("d").unwrap().as_f64(),
            Some(-2.5f64)
        );
        let out = v.to_string();
        let v2 = parse(&out).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn escapes() {
        let v = Json::Str("line\n\"quoted\"\ttab\\".into());
        let s = v.to_string();
        assert_eq!(parse(&s).unwrap(), v);
    }

    #[test]
    fn pretty_is_parseable() {
        let mut o = Json::obj();
        o.set("id", Json::Str("abc".into()));
        o.set("nested", Json::Arr(vec![Json::Int(1), Json::obj()]));
        let p = o.to_string_pretty();
        assert!(p.contains('\n'));
        assert_eq!(parse(&p).unwrap(), o);
    }

    #[test]
    fn rejects_trailing_garbage() {
        assert!(parse("{} junk").is_err());
        assert!(parse("").is_err());
        assert!(parse("{\"a\":}").is_err());
    }

    #[test]
    fn unicode_passthrough() {
        let v = parse(r#"{"k":"héllo \u00e9"}"#).unwrap();
        assert_eq!(v.get("k").unwrap().as_str(), Some("héllo é"));
    }

    #[test]
    fn malformed_input_never_panics() {
        let cases = [
            "",
            "{",
            "}",
            "[",
            "{\"a\":",
            "{\"a\":}",
            "[1,",
            "\"unterminated",
            "\"\\u00\"",
            "\"\\q\"",
            "nul",
            "01",
            "-",
            "1e",
            "{\"caf\u{e9}\": \"\u{1f600}\"}",
            "\u{1f600}",
        ];
        for c in cases {
            let _ = parse(c);
        }
    }
}
