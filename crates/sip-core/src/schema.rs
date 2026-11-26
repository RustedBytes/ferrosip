//! Module parameter schemas: the types, defaults and docs of each
//! module's parameters, declared next to the module (`Module::params`).
//! ferrosip.toml is validated and converted with them (to the `Arg`s a
//! `modparam` would pass); `ferrosip check --explain` and
//! `ferrosip schema` print them.

use crate::Arg;

/// The unit a module expects a duration in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    Ms,
    Sec,
}

#[derive(Clone, Copy, Debug)]
pub enum Ty {
    Str,
    /// An integer within `min..=max`.
    Int {
        min: i64,
        max: i64,
    },
    /// `true`/`false`; given to the module as 1/0.
    Bool,
    /// `"500ms"`, `"30s"`, `"2m"`, `"1h"`, `"1d"`, `"1h30m"`, or a bare
    /// number already in `Unit`.
    Duration(Unit),
    /// One of the names; the module gets the paired value (e.g.
    /// `("write-back", "2")` for Kamailio's numeric `db_mode`).
    Enum(&'static [(&'static str, &'static str)]),
    /// Several values: one `modparam` each.
    List(&'static Ty),
}

pub const ANY_INT: Ty = Ty::Int { min: i64::MIN, max: i64::MAX };
pub const UINT: Ty = Ty::Int { min: 0, max: i64::MAX };

impl Ty {
    pub fn describe(&self) -> String {
        match self {
            Ty::Str => "string".into(),
            Ty::Int { min, max } => match (*min, *max) {
                (i64::MIN, i64::MAX) => "int".into(),
                (lo, i64::MAX) => format!("int ≥ {lo}"),
                (lo, hi) => format!("int {lo}..{hi}"),
            },
            Ty::Bool => "bool".into(),
            Ty::Duration(Unit::Ms) => "duration (bare numbers: ms)".into(),
            Ty::Duration(Unit::Sec) => "duration (bare numbers: s)".into(),
            Ty::Enum(v) => format!("one of {}", v.iter().map(|(n, _)| format!("\"{n}\"")).collect::<Vec<_>>().join(", ")),
            Ty::List(t) => format!("list of {}", t.describe()),
        }
    }
}

/// One parameter of a module.
#[derive(Clone, Copy, Debug)]
pub struct ParamSpec {
    pub name: &'static str,
    pub ty: Ty,
    /// As written in ferrosip.toml ("" = no default / required by context).
    pub default: &'static str,
    pub doc: &'static str,
    /// Changing it applies on `cfg.reload` (otherwise a restart).
    pub reload: bool,
}

/// `ParamSpec` without the noise: `p("fr_timer", Ty::Duration(Unit::Ms), "30s", "…")`.
pub const fn p(name: &'static str, ty: Ty, default: &'static str, doc: &'static str) -> ParamSpec {
    ParamSpec { name, ty, default, doc, reload: false }
}

/// A parameter `cfg.reload` can change on a running server (the module
/// reads it at use time).
pub const fn pr(name: &'static str, ty: Ty, default: &'static str, doc: &'static str) -> ParamSpec {
    ParamSpec { name, ty, default, doc, reload: true }
}

/// A value from the config file, independent of the file format.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    List(Vec<Value>),
}

impl Value {
    pub fn kind(&self) -> &'static str {
        match self {
            Value::Str(_) => "a string",
            Value::Int(_) => "an integer",
            Value::Float(_) => "a number",
            Value::Bool(_) => "a boolean",
            Value::List(_) => "a list",
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Str(s) => write!(f, "{s:?}"),
            Value::Int(i) => write!(f, "{i}"),
            Value::Float(x) => write!(f, "{x}"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::List(v) => write!(f, "[{}]", v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", ")),
        }
    }
}

/// `"1h30m"`, `"500ms"`, `"2d"` → milliseconds.
pub fn parse_duration_ms(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let (mut total, mut rest) = (0u64, s);
    while !rest.is_empty() {
        let digits = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        if digits == 0 {
            return Err(format!("{s:?}: expected a number before {rest:?}"));
        }
        let (num, after) = rest.split_at(digits);
        let n: u64 = num.parse().map_err(|_| format!("{s:?}: number too large"))?;
        let unit_len = after.find(|c: char| c.is_ascii_digit()).unwrap_or(after.len());
        let (unit, after) = after.split_at(unit_len);
        rest = after;
        let mult = match unit {
            "ms" => 1,
            "s" => 1_000,
            "m" => 60_000,
            "h" => 3_600_000,
            "d" => 86_400_000,
            "" => return Err(format!("{s:?}: missing unit (ms, s, m, h, d)")),
            u => return Err(format!("{s:?}: unknown unit {u:?} (ms, s, m, h, d)")),
        };
        total = n.checked_mul(mult).and_then(|x| total.checked_add(x)).ok_or_else(|| format!("{s:?}: too large"))?;
    }
    Ok(total)
}

fn int_of(v: &Value) -> Option<i64> {
    match v {
        Value::Int(i) => Some(*i),
        Value::Str(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Validate `v` against `spec` and turn it into the `modparam` values the
/// module expects (several for a list).
pub fn convert(spec: &ParamSpec, v: &Value) -> Result<Vec<Arg>, String> {
    convert_ty(&spec.ty, v)
}

fn convert_ty(ty: &Ty, v: &Value) -> Result<Vec<Arg>, String> {
    let one = |a: Arg| Ok(vec![a]);
    match ty {
        Ty::Str => match v {
            Value::Str(s) => one(Arg::Str(s.clone())),
            other => Err(format!("expected a string, got {} ({other})", other.kind())),
        },
        Ty::Int { min, max } => {
            let i = int_of(v).ok_or_else(|| format!("expected an integer, got {} ({v})", v.kind()))?;
            if i < *min || i > *max {
                return Err(format!("{i} is out of range ({})", ty.describe()));
            }
            one(Arg::Int(i))
        }
        Ty::Bool => {
            let b = match v {
                Value::Bool(b) => *b,
                Value::Int(0) => false,
                Value::Int(1) => true,
                Value::Str(s) => match s.trim().to_ascii_lowercase().as_str() {
                    "true" | "yes" | "on" | "1" => true,
                    "false" | "no" | "off" | "0" => false,
                    _ => return Err(format!("expected true or false, got {v}")),
                },
                other => return Err(format!("expected true or false, got {} ({other})", other.kind())),
            };
            one(Arg::Int(i64::from(b)))
        }
        Ty::Duration(unit) => {
            let ms = match v {
                Value::Int(i) if *i >= 0 => {
                    return one(Arg::Int(*i));
                }
                Value::Str(s) => parse_duration_ms(s)?,
                other => return Err(format!("expected a duration like \"30s\", got {} ({other})", other.kind())),
            };
            let n = match unit {
                Unit::Ms => ms,
                Unit::Sec if ms % 1000 == 0 => ms / 1000,
                Unit::Sec => return Err(format!("{v} is not a whole number of seconds")),
            };
            one(Arg::Int(i64::try_from(n).map_err(|_| format!("{v}: too large"))?))
        }
        Ty::Enum(values) => {
            let s = match v {
                Value::Str(s) => s.as_str(),
                other => return Err(format!("expected one of {}, got {} ({other})", names(values), other.kind())),
            };
            let Some((_, mapped)) = values.iter().find(|(n, _)| n.eq_ignore_ascii_case(s)) else {
                return Err(format!("{s:?} is not one of {}{}", names(values), suggest(s, values.iter().map(|(n, _)| *n))));
            };
            one(match mapped.parse::<i64>() {
                Ok(i) => Arg::Int(i),
                Err(_) => Arg::Str(mapped.to_string()),
            })
        }
        Ty::List(inner) => match v {
            Value::List(items) => {
                let mut out = Vec::new();
                for (n, item) in (1usize..).zip(items) {
                    out.extend(convert_ty(inner, item).map_err(|e| format!("item {n}: {e}"))?);
                }
                Ok(out)
            }
            single => convert_ty(inner, single),
        },
    }
}

fn names(values: &[(&str, &str)]) -> String {
    values.iter().map(|(n, _)| format!("\"{n}\"")).collect::<Vec<_>>().join(", ")
}

/// Levenshtein distance, for "did you mean".
pub fn distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    // prev[j]: distance between the chars of `a` so far and b[..j].
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in (1usize..).zip(a.chars()) {
        let mut cur = Vec::with_capacity(prev.len());
        cur.push(i);
        for (cb, w) in b.iter().zip(prev.windows(2)) {
            let &[diag, up] = w else { continue };
            let left = cur.last().copied().unwrap_or(i);
            cur.push(diag.saturating_add(usize::from(ca != *cb)).min(up.saturating_add(1)).min(left.saturating_add(1)));
        }
        prev = cur;
    }
    prev.last().copied().unwrap_or_default()
}

/// `" (did you mean \"x\"?)"` when one candidate is close, else "".
pub fn suggest<'a>(word: &str, candidates: impl IntoIterator<Item = &'a str>) -> String {
    let best = candidates.into_iter().map(|c| (distance(word, c), c)).min();
    match best {
        Some((d, c)) if d <= 2.max(word.len() / 3) && d > 0 => format!(" (did you mean \"{c}\"?)"),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(ty: Ty, v: Value) -> Result<Vec<Arg>, String> {
        convert(&p("x", ty, "", ""), &v)
    }

    fn ints(r: Result<Vec<Arg>, String>) -> Vec<i64> {
        r.unwrap().iter().map(|a| a.int().unwrap()).collect()
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration_ms("500ms"), Ok(500));
        assert_eq!(parse_duration_ms("30s"), Ok(30_000));
        assert_eq!(parse_duration_ms("1h30m"), Ok(5_400_000));
        assert_eq!(parse_duration_ms("2d"), Ok(172_800_000));
        assert!(parse_duration_ms("30").unwrap_err().contains("missing unit"));
        assert!(parse_duration_ms("3x").unwrap_err().contains("unknown unit"));
        assert!(parse_duration_ms("s").is_err());
        assert_eq!(ints(args(Ty::Duration(Unit::Ms), Value::Str("2s".into()))), vec![2000]);
        assert_eq!(ints(args(Ty::Duration(Unit::Sec), Value::Str("1h".into()))), vec![3600]);
        assert_eq!(ints(args(Ty::Duration(Unit::Sec), Value::Int(90))), vec![90], "bare number: the module's unit");
        assert!(args(Ty::Duration(Unit::Sec), Value::Str("1500ms".into())).unwrap_err().contains("whole number of seconds"));
    }

    #[test]
    fn types() {
        assert_eq!(ints(args(Ty::Bool, Value::Bool(true))), vec![1]);
        assert_eq!(ints(args(Ty::Bool, Value::Str("off".into()))), vec![0]);
        assert!(args(Ty::Bool, Value::Int(5)).is_err());
        assert_eq!(ints(args(UINT, Value::Str("42".into()))), vec![42], "env-interpolated numbers are strings");
        assert!(args(Ty::Int { min: 1, max: 10 }, Value::Int(11)).unwrap_err().contains("out of range"));
        assert!(args(Ty::Str, Value::Int(1)).unwrap_err().contains("expected a string"));
        const DB: Ty = Ty::Enum(&[("off", "0"), ("write-through", "1"), ("write-back", "2")]);
        assert_eq!(ints(args(DB, Value::Str("write-back".into()))), vec![2]);
        let e = args(DB, Value::Str("write-bak".into())).unwrap_err();
        assert!(e.contains("did you mean \"write-back\"") && e.contains("\"off\""), "{e}");
        const NAMED: Ty = Ty::Enum(&[("strict", "strict")]);
        assert_eq!(args(NAMED, Value::Str("STRICT".into())).unwrap()[0].str().unwrap(), "strict");
        const SOCKS: Ty = Ty::List(&Ty::Str);
        let v = args(SOCKS, Value::List(vec![Value::Str("a".into()), Value::Str("b".into())])).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(args(SOCKS, Value::Str("one".into())).unwrap().len(), 1, "a single value is a one-item list");
        assert!(args(SOCKS, Value::List(vec![Value::Int(1)])).unwrap_err().starts_with("item 1:"));
    }

    #[test]
    fn suggestions() {
        assert_eq!(distance("kitten", "sitting"), 3);
        assert_eq!(suggest("fr_timr", ["fr_timer", "fr_inv_timer"]), " (did you mean \"fr_timer\"?)");
        assert_eq!(suggest("zzzz", ["fr_timer"]), "");
    }
}
