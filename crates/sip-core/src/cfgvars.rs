//! Custom config variables (Kamailio's `group.name = value desc "…"` lines).
//!
//! Declared once at startup from the config file, read in scripts with
//! `$sel(cfg_get.group.name)` and changed at runtime over RPC
//! (`cfg.set_now_int`, `cfg.set_now_string`); the type stays what the
//! declaration gave it.

use crate::pv::Val;
use crate::sync::{read, write};
use std::collections::BTreeMap;
use std::sync::{OnceLock, RwLock};

struct Var {
    val: Val,
    desc: String,
}

fn vars() -> &'static RwLock<BTreeMap<String, Var>> {
    static V: OnceLock<RwLock<BTreeMap<String, Var>>> = OnceLock::new();
    V.get_or_init(Default::default)
}

/// Parse a declaration value: `"text"`, `'text'` or an integer, optionally
/// followed by `desc "…"`.
pub fn parse_decl(v: &str) -> Result<(Val, String), String> {
    let v = v.trim();
    let (val, rest) = match v.chars().next() {
        Some(q @ ('"' | '\'')) => {
            let (text, rest) = v.strip_prefix(q).and_then(|b| b.split_once(q)).ok_or_else(|| format!("unterminated string in {v:?}"))?;
            (Val::Str(text.to_string()), rest)
        }
        _ => {
            let (num, rest) = v.split_once(char::is_whitespace).unwrap_or((v, ""));
            let n = num.parse::<i64>().map_err(|_| format!("expected a string or integer, got {num:?}"))?;
            (Val::Int(n), rest)
        }
    };
    let rest = rest.trim();
    let desc = match rest.strip_prefix("desc") {
        Some(d) => d.trim().trim_matches(|c| c == '"' || c == '\'').to_string(),
        None if rest.is_empty() => String::new(),
        None => return Err(format!("unexpected {rest:?} after the value")),
    };
    Ok((val, desc))
}

/// Declare (or redeclare, on reload) `group.name`.
pub fn declare(name: &str, val: Val, desc: String) {
    write(vars()).insert(name.to_string(), Var { val, desc });
}

pub fn exists(name: &str) -> bool {
    read(vars()).contains_key(name)
}

pub fn get(name: &str) -> Option<Val> {
    read(vars()).get(name).map(|v| v.val.clone())
}

/// Change a declared variable; the new value must have the declared type.
pub fn set(name: &str, val: Val) -> Result<(), String> {
    let mut g = write(vars());
    let var = g.get_mut(name).ok_or_else(|| format!("no config variable {name}"))?;
    if std::mem::discriminant(&var.val) != std::mem::discriminant(&val) {
        return Err(format!("{name} has a different type"));
    }
    var.val = val;
    Ok(())
}

/// `(name, value, description)` of every variable, sorted by name.
pub fn list() -> Vec<(String, Val, String)> {
    read(vars()).iter().map(|(k, v)| (k.clone(), v.val.clone(), v.desc.clone())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declarations() {
        assert_eq!(parse_decl(r#""10.0.0.1" desc "PSTN GW""#).unwrap(), (Val::Str("10.0.0.1".into()), "PSTN GW".into()));
        assert_eq!(parse_decl("5").unwrap(), (Val::Int(5), String::new()));
        assert!(parse_decl("abc").is_err());
        declare("t.x", Val::Int(1), String::new());
        assert!(set("t.x", Val::Str("a".into())).is_err(), "type is fixed");
        set("t.x", Val::Int(7)).unwrap();
        assert_eq!(get("t.x"), Some(Val::Int(7)));
    }
}
