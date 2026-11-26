//! JSON paths for the script (`{json.parse,path}`, jansson): `a.b[2].c`
//! walks objects by key and arrays by index (`a.b.2` works too).

use crate::pv::Val;
use serde_json::{Map, Value};

#[derive(Debug, PartialEq)]
enum Step {
    Key(String),
    Idx(usize),
}

fn steps(path: &str) -> Vec<Step> {
    let mut out = Vec::new();
    for part in path.split('.').filter(|p| !p.is_empty()) {
        let (key, rest) = part.find('[').map_or((part, ""), |i| part.split_at(i));
        if !key.is_empty() {
            match key.parse::<usize>() {
                Ok(i) if rest.is_empty() && key.chars().all(|c| c.is_ascii_digit()) => out.push(Step::Idx(i)),
                _ => out.push(Step::Key(key.to_string())),
            }
        }
        for idx in rest.split('[').filter(|s| !s.is_empty()) {
            if let Ok(i) = idx.trim_end_matches(']').trim().parse() {
                out.push(Step::Idx(i));
            }
        }
    }
    out
}

/// The value at `path` (empty path = the document).
pub fn get<'v>(v: &'v Value, path: &str) -> Option<&'v Value> {
    let mut cur = v;
    for s in steps(path) {
        cur = match (s, cur) {
            (Step::Key(k), Value::Object(m)) => m.get(&k)?,
            (Step::Idx(i), Value::Array(a)) => a.get(i)?,
            (Step::Idx(i), Value::Object(m)) => m.get(&i.to_string())?,
            _ => return None,
        };
    }
    Some(cur)
}

/// Largest run of `null`s `slot` creates to reach an array index.
const MAX_GAP: usize = 1024;

/// A mutable slot at `path`, creating objects/arrays on the way (`None`
/// for an index more than `MAX_GAP` past the end).
pub fn slot<'v>(v: &'v mut Value, path: &str) -> Option<&'v mut Value> {
    let mut cur = v;
    for s in steps(path) {
        cur = match s {
            Step::Key(k) => {
                if !cur.is_object() {
                    *cur = Value::Object(Map::new());
                }
                cur.as_object_mut()?.entry(k).or_insert(Value::Null)
            }
            Step::Idx(i) => {
                if !cur.is_array() {
                    *cur = Value::Array(Vec::new());
                }
                let a = cur.as_array_mut()?;
                // The path can come from message content: never let an index
                // allocate a huge array (fills at most MAX_GAP nulls).
                if i.saturating_sub(a.len()) > MAX_GAP {
                    return None;
                }
                if a.len() <= i {
                    a.resize(i.checked_add(1)?, Value::Null);
                }
                a.get_mut(i)?
            }
        };
    }
    Some(cur)
}

/// JSON value → script value: strings unquoted, integers and booleans as
/// integers, null as `$null`, anything else as JSON text.
pub fn to_val(v: &Value) -> Val {
    match v {
        Value::Null => Val::Null,
        Value::Bool(b) => Val::Int(i64::from(*b)),
        Value::String(s) => Val::Str(s.clone()),
        Value::Number(n) => n.as_i64().map_or_else(|| Val::Str(n.to_string()), Val::Int),
        other => Val::Str(other.to_string()),
    }
}

/// A typed value for jansson_set/append ("string", "integer", "real",
/// "true", "false", "null", "object", "array").
pub fn typed(ty: &str, v: &str) -> Result<Value, String> {
    Ok(match ty.to_ascii_lowercase().as_str() {
        "string" | "str" => Value::String(v.to_string()),
        "integer" | "int" => Value::from(v.trim().parse::<i64>().map_err(|_| format!("not an integer: {v:?}"))?),
        "real" => Value::from(v.trim().parse::<f64>().map_err(|_| format!("not a number: {v:?}"))?),
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        "null" => Value::Null,
        "object" | "obj" | "array" | "json" => serde_json::from_str(v).map_err(|e| format!("bad JSON value: {e}"))?,
        t => return Err(format!("unknown JSON type {t:?}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        let v: Value = serde_json::from_str(r#"{"a":{"b":[1,{"c":"x"}]},"n":5,"t":true}"#).unwrap();
        assert_eq!(get(&v, "a.b[1].c"), Some(&Value::from("x")));
        assert_eq!(get(&v, "a.b.0"), Some(&Value::from(1)));
        assert_eq!(to_val(get(&v, "t").unwrap()), Val::Int(1));
        assert_eq!(to_val(get(&v, "a.b").unwrap()), Val::Str(r#"[1,{"c":"x"}]"#.into()));
        assert!(get(&v, "a.z").is_none());
        let mut w = Value::Null;
        *slot(&mut w, "x.y[1]").unwrap() = Value::from("z");
        assert_eq!(w.to_string(), r#"{"x":{"y":[null,"z"]}}"#);
        // Found by fuzzing: a huge index must not allocate.
        assert!(slot(&mut w, "x.y.124091496160956397").is_none());
    }
}
