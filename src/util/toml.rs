//! A deliberately small TOML subset parser.
//!
//! It lowers a TOML document into the same [`Json`] value tree used
//! everywhere else, so `--config foo.toml` and `--config foo.json` feed the
//! exact same configuration loader.
//!
//! Supported: comments, bare/quoted keys, `[table]`, `[table.sub]`,
//! `[[array-of-tables]]`, strings (basic + literal), integers (with `_`
//! separators, hex/octal/binary prefixes), floats, booleans, and arrays
//! written on one line or spread over several.  Not supported: inline
//! tables, dates, multi-line strings.  Those are rejected with a clear error
//! rather than silently mis-parsed.

use super::json::Json;
use crate::error::{Error, Result};

pub fn parse(input: &str) -> Result<Json> {
    let mut root = Json::obj();
    // Path of the table that bare `key = value` lines currently target.
    let mut cur: Vec<String> = Vec::new();

    for (lineno, line) in logical_lines(input)? {
        let line = line.as_str();
        let err = |m: String| Error::parse(format!("{} (line {})", m, lineno + 1));

        if line.starts_with("[[") {
            if !line.ends_with("]]") {
                return Err(err("unterminated [[array of tables]] header".into()));
            }
            let path = split_key_path(&line[2..line.len() - 2])?;
            push_array_table(&mut root, &path).map_err(err)?;
            cur = path;
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err(err("unterminated [table] header".into()));
            }
            let path = split_key_path(&line[1..line.len() - 1])?;
            ensure_table(&mut root, &path).map_err(err)?;
            cur = path;
            continue;
        }

        let eq = match line.find('=') {
            Some(i) => i,
            None => return Err(err(format!("expected `key = value`, got {:?}", line))),
        };
        let key = unquote_key(line[..eq].trim())?;
        let value = parse_value(line[eq + 1..].trim()).map_err(|e| err(e.to_string()))?;
        let table = table_at(&mut root, &cur).map_err(err)?;
        table.set(key, value);
    }
    Ok(root)
}

/// Net bracket depth of `s`, ignoring brackets inside quoted strings.
fn bracket_depth(s: &str) -> i32 {
    let b = s.as_bytes();
    let mut depth = 0i32;
    let (mut in_basic, mut in_literal) = (false, false);
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if in_basic => i += 1, // skip the escaped byte
            b'"' if !in_literal => in_basic = !in_basic,
            b'\'' if !in_basic => in_literal = !in_literal,
            b'[' if !in_basic && !in_literal => depth += 1,
            b']' if !in_basic && !in_literal => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    depth
}

/// Fold physical lines into logical ones, joining arrays that span several
/// lines.
///
/// Multi-line arrays are ordinary TOML and common in real config files, so
/// the parser accepts them; the alternative is a `masked_paths` list written
/// as one unreadable 200-column line. Comments are stripped per physical
/// line before joining, so a `# comment` inside an array does not swallow the
/// rest of it. The reported line number is that of the line the value
/// started on, which is what a reader looking for the error wants.
fn logical_lines(input: &str) -> Result<Vec<(usize, String)>> {
    let physical: Vec<&str> = input.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < physical.len() {
        let start = i;
        let first = strip_comment(physical[i]).trim().to_string();
        i += 1;
        if first.is_empty() {
            continue;
        }
        // Table headers are always single-line; only values can continue.
        if first.starts_with('[') && !first.contains('=') {
            out.push((start, first));
            continue;
        }
        let mut joined = first;
        let mut depth = bracket_depth(&joined);
        while depth > 0 {
            if i >= physical.len() {
                return Err(Error::parse(format!(
                    "unterminated array starting on line {}",
                    start + 1
                )));
            }
            let next = strip_comment(physical[i]).trim();
            i += 1;
            if !next.is_empty() {
                joined.push(' ');
                joined.push_str(next);
                depth = bracket_depth(&joined);
            }
        }
        out.push((start, joined));
    }
    Ok(out)
}

fn strip_comment(line: &str) -> &str {
    let b = line.as_bytes();
    let mut in_basic = false;
    let mut in_literal = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if in_basic => i += 1,
            b'"' if !in_literal => in_basic = !in_basic,
            b'\'' if !in_basic => in_literal = !in_literal,
            b'#' if !in_basic && !in_literal => return &line[..i],
            _ => {}
        }
        i += 1;
    }
    line
}

fn split_key_path(s: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for part in s.split('.') {
        let p = part.trim();
        if p.is_empty() {
            return Err(Error::parse("empty key segment in table header"));
        }
        out.push(unquote_key(p)?);
    }
    Ok(out)
}

fn unquote_key(k: &str) -> Result<String> {
    if k.len() >= 2 && (k.starts_with('"') && k.ends_with('"')) {
        return Ok(k[1..k.len() - 1].to_string());
    }
    if k.len() >= 2 && (k.starts_with('\'') && k.ends_with('\'')) {
        return Ok(k[1..k.len() - 1].to_string());
    }
    if k.is_empty() {
        return Err(Error::parse("empty key"));
    }
    Ok(k.to_string())
}

/// Navigate to (creating as needed) the table at `path`.
fn table_at<'a>(root: &'a mut Json, path: &[String]) -> std::result::Result<&'a mut Json, String> {
    let mut node = root;
    for seg in path {
        if node.get(seg).is_none() {
            node.set(seg.clone(), Json::obj());
        }
        // `set` is a no-op on a non-object, so this can only be None if the
        // caller handed us a root that is not a table. Report it rather than
        // panicking: the input is a user-supplied config file.
        node = match node.get_mut(seg) {
            Some(n) => n,
            None => return Err(format!("`{}` is not a table", seg)),
        };
        // When the segment is an array-of-tables, target its last element.
        if let Json::Arr(a) = node {
            if a.is_empty() {
                return Err(format!("array of tables `{}` is empty", seg));
            }
            let n = a.len() - 1;
            node = &mut a[n];
        }
        if !matches!(node, Json::Obj(_)) {
            return Err(format!("`{}` is not a table", seg));
        }
    }
    Ok(node)
}

fn ensure_table(root: &mut Json, path: &[String]) -> std::result::Result<(), String> {
    table_at(root, path).map(|_| ())
}

fn push_array_table(root: &mut Json, path: &[String]) -> std::result::Result<(), String> {
    let (last, parents) = match path.split_last() {
        Some(x) => x,
        None => return Err("empty table path".into()),
    };
    let parent = table_at(root, parents)?;
    if parent.get(last).is_none() {
        parent.set(last.clone(), Json::Arr(Vec::new()));
    }
    match parent.get_mut(last) {
        Some(Json::Arr(a)) => {
            a.push(Json::obj());
            Ok(())
        }
        _ => Err(format!("`{}` is not an array of tables", last)),
    }
}

fn parse_value(s: &str) -> Result<Json> {
    if s.is_empty() {
        return Err(Error::parse("missing value"));
    }
    if s.starts_with("\"\"\"") || s.starts_with("'''") {
        return Err(Error::parse("multi-line strings are not supported"));
    }
    if s.starts_with('{') {
        return Err(Error::parse("inline tables are not supported"));
    }
    if s.starts_with('"') {
        return Ok(Json::Str(parse_basic_string(s)?));
    }
    if s.starts_with('\'') {
        if !s.ends_with('\'') || s.len() < 2 {
            return Err(Error::parse("unterminated literal string"));
        }
        return Ok(Json::Str(s[1..s.len() - 1].to_string()));
    }
    if s.starts_with('[') {
        if !s.ends_with(']') {
            return Err(Error::parse(
                "unterminated array: the brackets do not balance",
            ));
        }
        let inner = &s[1..s.len() - 1];
        let mut out = Vec::new();
        for item in split_top_level(inner) {
            let t = item.trim();
            if t.is_empty() {
                continue;
            }
            out.push(parse_value(t)?);
        }
        return Ok(Json::Arr(out));
    }
    if s == "true" {
        return Ok(Json::Bool(true));
    }
    if s == "false" {
        return Ok(Json::Bool(false));
    }
    parse_number(s)
}

fn parse_number(s: &str) -> Result<Json> {
    let cleaned: String = s.chars().filter(|c| *c != '_').collect();
    let (sign, body) = if let Some(r) = cleaned.strip_prefix('-') {
        (-1i64, r.to_string())
    } else if let Some(r) = cleaned.strip_prefix('+') {
        (1i64, r.to_string())
    } else {
        (1i64, cleaned.clone())
    };
    let radix_parsed = if let Some(h) = body.strip_prefix("0x") {
        Some(i64::from_str_radix(h, 16))
    } else if let Some(o) = body.strip_prefix("0o") {
        Some(i64::from_str_radix(o, 8))
    } else if let Some(bn) = body.strip_prefix("0b") {
        Some(i64::from_str_radix(bn, 2))
    } else {
        None
    };
    if let Some(r) = radix_parsed {
        return r
            .map(|v| Json::Int(sign * v))
            .map_err(|e| Error::parse(format!("bad integer {:?}: {}", s, e)));
    }
    if let Ok(i) = cleaned.parse::<i64>() {
        return Ok(Json::Int(i));
    }
    if let Ok(f) = cleaned.parse::<f64>() {
        return Ok(Json::Float(f));
    }
    Err(Error::parse(format!(
        "unrecognised value {:?} (strings must be quoted)",
        s
    )))
}

fn parse_basic_string(s: &str) -> Result<String> {
    let b = s.as_bytes();
    if b.len() < 2 || b[0] != b'"' {
        return Err(Error::parse("unterminated string"));
    }
    let mut out = String::new();
    let mut i = 1;
    loop {
        if i >= b.len() {
            return Err(Error::parse("unterminated string"));
        }
        match b[i] {
            b'"' => {
                if i + 1 != b.len() {
                    return Err(Error::parse("trailing data after string value"));
                }
                return Ok(out);
            }
            b'\\' => {
                i += 1;
                if i >= b.len() {
                    return Err(Error::parse("unterminated escape"));
                }
                match b[i] {
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    b'r' => out.push('\r'),
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'0' => out.push('\0'),
                    b'u' => {
                        if i + 5 > b.len() {
                            return Err(Error::parse("truncated \\u escape"));
                        }
                        let hex = &s[i + 1..i + 5];
                        let cp = u32::from_str_radix(hex, 16)
                            .map_err(|_| Error::parse("bad \\u escape"))?;
                        out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                        i += 4;
                    }
                    other => {
                        return Err(Error::parse(format!("unknown escape \\{}", other as char)))
                    }
                }
                i += 1;
            }
            _ => {
                // `i` is a byte index. Every other branch advances by whole
                // characters or by ASCII bytes, so it should always be on a
                // char boundary — but slicing a &str at a non-boundary
                // panics, and this is parsing a user-supplied file, so step
                // over the byte instead of trusting the invariant.
                match s.get(i..).and_then(|rest| rest.chars().next()) {
                    Some(ch) => {
                        out.push(ch);
                        i += ch.len_utf8();
                    }
                    None => i += 1,
                }
            }
        }
    }
}

/// Split on commas that are not inside quotes or nested brackets.
fn split_top_level(s: &str) -> Vec<&str> {
    let b = s.as_bytes();
    let mut parts = Vec::new();
    let (mut start, mut depth) = (0usize, 0i32);
    let (mut in_basic, mut in_literal) = (false, false);
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if in_basic => i += 1,
            b'"' if !in_literal => in_basic = !in_basic,
            b'\'' if !in_basic => in_literal = !in_literal,
            b'[' if !in_basic && !in_literal => depth += 1,
            b']' if !in_basic && !in_literal => depth -= 1,
            b',' if depth == 0 && !in_basic && !in_literal => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    parts.push(&s[start..]);
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# a comment
rootfs = "/var/lib/myrun/rootfs"   # trailing comment
command = ["/bin/sh", "-c", "echo hi"]
read_only = true

[resources]
memory = "256m"
cpus = 1.5
pids = 100

[network]
mode = "bridge"

[[network.publish]]
host = 8080
container = 80

[[network.publish]]
host = 9090
container = 90
"#;

    #[test]
    fn parses_sample() {
        let v = parse(SAMPLE).unwrap();
        assert_eq!(
            v.get("rootfs").unwrap().as_str(),
            Some("/var/lib/myrun/rootfs")
        );
        assert_eq!(v.get("command").unwrap().as_array().unwrap().len(), 3);
        assert_eq!(v.get("read_only").unwrap().as_bool(), Some(true));
        let r = v.get("resources").unwrap();
        assert_eq!(r.get("memory").unwrap().as_str(), Some("256m"));
        assert_eq!(r.get("cpus").unwrap().as_f64(), Some(1.5));
        assert_eq!(r.get("pids").unwrap().as_i64(), Some(100));
        let pubs = v
            .get("network")
            .unwrap()
            .get("publish")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(pubs.len(), 2);
        assert_eq!(pubs[1].get("host").unwrap().as_i64(), Some(9090));
    }

    #[test]
    fn hash_inside_string_is_not_a_comment() {
        let v = parse(r#"a = "x # y""#).unwrap();
        assert_eq!(v.get("a").unwrap().as_str(), Some("x # y"));
    }

    #[test]
    fn numeric_forms() {
        let v = parse("a = 1_000\nb = 0x10\nc = -3\nd = 0b101\n").unwrap();
        assert_eq!(v.get("a").unwrap().as_i64(), Some(1000));
        assert_eq!(v.get("b").unwrap().as_i64(), Some(16));
        assert_eq!(v.get("c").unwrap().as_i64(), Some(-3));
        assert_eq!(v.get("d").unwrap().as_i64(), Some(5));
    }

    #[test]
    fn unsupported_constructs_are_rejected() {
        assert!(parse("a = { b = 1 }").is_err());
        assert!(parse("a = bareword").is_err());
        assert!(parse("nonsense line").is_err());
    }

    #[test]
    fn malformed_input_never_panics() {
        // A config file is user-supplied, so the parser has to return errors
        // rather than unwinding. These inputs exercise the indexing paths.
        let cases = [
            "",
            "[",
            "[]",
            "[[",
            "a.b.c = ",
            "= 5",
            "\"unterminated",
            "k = \"\\u12",
            "k = \"\\q\"",
            "k = [1, 2",
            "[a]\nb = 1\n[a.b.c]\nd = 2",
            "k = \"caf\u{e9} \u{1f600}\"",
            "\u{1f600} = 1",
            "k = '\u{1f600}unterminated",
            "[[x]]\n[x.y]\nz = 1",
            "k=1\nk=2",
        ];
        for c in cases {
            // Ok or Err, but never a panic and never a hang.
            let _ = parse(c);
        }
    }

    #[test]
    fn multibyte_strings_round_trip() {
        let doc = parse("k = \"caf\u{e9} \u{1f600} ok\"").unwrap();
        assert_eq!(
            doc.get("k").and_then(|v| v.as_str()),
            Some("caf\u{e9} \u{1f600} ok")
        );
    }

    #[test]
    fn multi_line_arrays() {
        let doc = parse(
            r#"
paths = [
    "/proc/kcore",   # a comment inside the array
    "/proc/keys",

    "/sys/firmware",
]
nested = [[1, 2], [3]]
after = 7
"#,
        )
        .unwrap();
        let paths = doc.get("paths").and_then(|v| v.as_array()).unwrap();
        assert_eq!(paths.len(), 3);
        assert_eq!(paths[0].as_str(), Some("/proc/kcore"));
        assert_eq!(paths[2].as_str(), Some("/sys/firmware"));
        // Parsing must resume correctly on the line after the array.
        assert_eq!(doc.get("after").and_then(|v| v.as_u64()), Some(7));
        assert_eq!(
            doc.get("nested").and_then(|v| v.as_array()).unwrap().len(),
            2
        );
    }

    #[test]
    fn brackets_inside_strings_do_not_extend_an_array() {
        let doc = parse("k = [\"a]b\", \"c[d\"]\nnext = 1").unwrap();
        assert_eq!(doc.get("k").and_then(|v| v.as_array()).unwrap().len(), 2);
        assert_eq!(doc.get("next").and_then(|v| v.as_u64()), Some(1));
    }

    #[test]
    fn unterminated_multi_line_array_is_an_error() {
        let e = parse("k = [\n  1,\n  2,\n").unwrap_err();
        assert!(e.to_string().contains("unterminated array"), "{}", e);
    }
}
