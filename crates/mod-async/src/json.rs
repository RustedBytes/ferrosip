//! `jansson` and `json`: read and build JSON documents in the script.
//!
//! * `jansson_get(path, json, $dst)`, `jansson_array_size(path, json, $dst)`,
//!   `jansson_set(type, path, value, $doc)`, `jansson_append(type, path,
//!   value, $doc)` (types: string, integer, real, true, false, null, object,
//!   array), `jansson_get_field(json, field, $dst)`, `jansson_xdecode(json,
//!   xavp)`, `jansson_xencode(xavp, $dst)`.
//! * `json_get_field(json, field, $dst)` and the `{json.parse,path}`
//!   transformation (in the core).

use serde_json::{Map, Value};
use sip_core::json::{get, slot, to_val, typed};
use sip_core::module::DynStr;
use sip_core::pv::{FmtPart, PvRef, Val};
use sip_core::schema::ParamSpec;
use sip_core::sig::{FnSig, Param};
use sip_core::{Arg, Ctx, Module, Registry, TxnVars};
use std::collections::HashMap;
use std::sync::Arc;

/// An output variable argument (`$var(x)`, `$avp(y)` …).
pub(crate) fn out_pv(a: &Arg) -> Result<PvRef, String> {
    match a {
        Arg::Fmt(f) => f.single_pv().cloned().ok_or_else(|| "expected a variable".to_string()),
        _ => Err("expected a variable".into()),
    }
}

fn parse(s: &str) -> Option<Value> {
    serde_json::from_str(s).ok()
}

#[derive(Default)]
pub struct Jansson {
    /// "json" or "jansson" (same functions, json only has json_get_field).
    name: &'static str,
}

impl Jansson {
    pub fn named(name: &'static str) -> Self {
        Self { name }
    }
}

fn set_out(ctx: &mut Ctx<'_, '_>, dst: &PvRef, v: Val) -> i32 {
    match dst.set(ctx, v) {
        Ok(()) => 1,
        Err(e) => {
            sip_core::log::log(sip_core::log::L_ERR, &format!("jansson: {e}"));
            -1
        }
    }
}

impl Module for Jansson {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const TYPES: &[&str] = &["string", "integer", "real", "true", "false", "null", "object", "array"];
        const FIELD: &[Param] = &[arg("json", Str), arg("field", Str), arg("result", Var)];
        const GET: &[Param] = &[arg("path", Str).eg("\"a.b[0]\""), arg("json", Str), arg("result", Var)];
        const SET: &[Param] = &[arg("type", Enum(TYPES)), arg("path", Str).eg("\"a.b\""), arg("value", Str), arg("doc", Var)];
        const XDECODE: &[Param] = &[arg("json", Str), arg("xavp", Str).lit()];
        const XENCODE: &[Param] = &[arg("xavp", Str).lit(), arg("result", Var)];
        let field = sig("json_get_field", "get_field", FIELD, Ret::Bool, "The value of a top-level `field` of `json`, into `result`").allowed(ctx::ANY);
        if self.name == "json" {
            return Some(vec![field]);
        }
        Some(vec![
            FnSig { name: "jansson_get_field", ..field },
            sig("jansson_get", "get", GET, Ret::Bool, "The value at `path` (a.b[0]) in `json`, into `result`; false when missing").allowed(ctx::ANY),
            sig("jansson_array_size", "array_size", GET, Ret::Bool, "The length of the array at `path` in `json`, into `result`").allowed(ctx::ANY),
            sig("jansson_set", "set", SET, Ret::Bool, "Set `path` in the JSON document `doc` (created if empty) to a value of `type`").allowed(ctx::ANY),
            sig("jansson_append", "append", SET, Ret::Bool, "Append a value of `type` to the array at `path` in the JSON document `doc`").allowed(ctx::ANY),
            sig("jansson_xdecode", "xdecode", XDECODE, Ret::Bool, "A JSON object (or array of objects) into items of $xavp(`xavp`)").allowed(ctx::ANY),
            sig("jansson_xencode", "xencode", XENCODE, Ret::Bool, "The first item of $xavp(`xavp`) as a JSON object, into `result`").allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let m = self.name;
        let field = |ctx: &mut Ctx, (j, f, dst): &(DynStr, DynStr, PvRef)| {
            let (j, f) = (j.eval(ctx).into_owned(), f.eval(ctx).into_owned());
            match parse(&j).as_ref().and_then(|v| v.get(&f)) {
                Some(v) => set_out(ctx, dst, to_val(v)),
                None => -1,
            }
        };
        let three = |a: &[Arg]| -> Result<(DynStr, DynStr, PvRef), String> {
            let [x, y, dst] = crate::fixed_args(a)?;
            Ok((x.dyn_str()?, y.dyn_str()?, out_pv(dst)?))
        };
        if m == "json" {
            reg.export(m, "json_get_field", three, field);
            return Ok(());
        }
        reg.export(m, "jansson_get_field", three, field);
        reg.export(m, "jansson_get", three, |ctx: &mut Ctx, (p, j, dst): &(DynStr, DynStr, PvRef)| {
            let (p, j) = (p.eval(ctx).into_owned(), j.eval(ctx).into_owned());
            match parse(&j).as_ref().and_then(|v| get(v, &p)) {
                Some(v) => set_out(ctx, dst, to_val(v)),
                None => -1,
            }
        });
        reg.export(m, "jansson_array_size", three, |ctx: &mut Ctx, (p, j, dst): &(DynStr, DynStr, PvRef)| {
            let (p, j) = (p.eval(ctx).into_owned(), j.eval(ctx).into_owned());
            match parse(&j).as_ref().and_then(|v| get(v, &p)).and_then(Value::as_array) {
                Some(a) => set_out(ctx, dst, Val::Int(i64::try_from(a.len()).unwrap_or(i64::MAX))),
                None => -1,
            }
        });
        let four = |a: &[Arg]| -> Result<(DynStr, DynStr, DynStr, PvRef), String> {
            let [x, y, z, dst] = crate::fixed_args(a)?;
            Ok((x.dyn_str()?, y.dyn_str()?, z.dyn_str()?, out_pv(dst)?))
        };
        for (name, append) in [("jansson_set", false), ("jansson_append", true)] {
            reg.export(m, name, four, move |ctx: &mut Ctx, (t, p, v, doc): &(DynStr, DynStr, DynStr, PvRef)| {
                let (t, p, v) = (t.eval(ctx).into_owned(), p.eval(ctx).into_owned(), v.eval(ctx).into_owned());
                let val = match typed(&t, &v) {
                    Ok(x) => x,
                    Err(e) => {
                        sip_core::log::log(sip_core::log::L_ERR, &format!("{name}: {e}"));
                        return -1;
                    }
                };
                let cur = doc.get(ctx);
                let mut root = if cur.is_null() { Value::Object(Map::new()) } else { parse(&cur.as_str()).unwrap_or(Value::Object(Map::new())) };
                let Some(s) = slot(&mut root, &p) else { return -1 };
                if append {
                    if !s.is_array() {
                        *s = Value::Array(Vec::new());
                    }
                    if let Some(a) = s.as_array_mut() {
                        a.push(val);
                    }
                } else {
                    *s = val;
                }
                set_out(ctx, doc, Val::Str(root.to_string()))
            });
        }
        // The xavp argument: a bare name (Kamailio's form) or "$xavp(name)",
        // which a script string brings as a format holding the variable.
        fn xavp_name(a: &Arg) -> Result<String, String> {
            match a {
                Arg::Str(s) => Ok(s.trim_start_matches("$xavp(").trim_end_matches(')').to_string()),
                Arg::Fmt(f) => match f.0.as_slice() {
                    [FmtPart::Pv(p)] if p.name == "xavp" => Ok(p.param.name.clone()),
                    _ => Err("expected an xavp name or \"$xavp(name)\"".into()),
                },
                Arg::Int(_) => Err("expected an xavp name or \"$xavp(name)\"".into()),
            }
        }
        // jansson_xdecode(json, xavp): an object → one item, an array of
        // objects → one item each (in order).
        reg.export(
            m,
            "jansson_xdecode",
            |a: &[Arg]| {
                let [json, xavp] = crate::fixed_args(a)?;
                Ok((json.dyn_str()?, xavp_name(xavp)?))
            },
            |ctx: &mut Ctx, (j, x): &(DynStr, String)| {
                let j = j.eval(ctx).into_owned();
                let Some(v) = parse(&j) else { return -1 };
                let objs: Vec<&Map<String, Value>> = match &v {
                    Value::Object(o) => vec![o],
                    Value::Array(a) => a.iter().filter_map(Value::as_object).collect(),
                    _ => return -1,
                };
                let items: Vec<HashMap<String, Val>> = objs.iter().map(|o| o.iter().map(|(k, v)| (k.clone(), to_val(v))).collect()).collect();
                ctx.ext_mut::<TxnVars>().xavps.insert(x.clone(), items);
                1
            },
        );
        reg.export(
            m,
            "jansson_xencode",
            |a: &[Arg]| {
                let [xavp, dst] = crate::fixed_args(a)?;
                Ok((xavp_name(xavp)?, out_pv(dst)?))
            },
            |ctx: &mut Ctx, (x, dst): &(String, PvRef)| {
                let Some(item) = ctx.ext::<TxnVars>().and_then(|t| t.xavps.get(x)).and_then(|v| v.first()).cloned() else { return -1 };
                let mut o = Map::new();
                let mut fields: Vec<(&String, &Val)> = item.iter().collect();
                fields.sort_by_key(|&(k, _)| k);
                for (k, v) in fields {
                    let v = match v {
                        Val::Null => Value::Null,
                        Val::Int(i) => Value::from(*i),
                        Val::Str(s) => Value::from(s.clone()),
                    };
                    o.insert(k.clone(), v);
                }
                set_out(ctx, dst, Val::Str(Value::Object(o).to_string()))
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_core::pv::parse_fmt;
    use sip_core::sync::lock;
    use sip_core::{Dest, Fmt, Outbound, Proto, RouteHub, RouteNames, RouteRunner};
    use std::sync::Mutex;

    /// Runs on the context before the function under test.
    type Before = Box<dyn Fn(&mut Ctx<'_, '_>) + Send + Sync>;

    struct NoNet;
    impl Outbound for NoNet {
        fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn advertise(&self, _: Proto) -> Option<std::net::SocketAddr> {
            None
        }
    }

    /// An event route that sets `$var(doc)`, runs one exported function,
    /// and reads `$var(out)` and `$var(doc)` back.
    struct Call {
        func: sip_core::ExportFn,
        fixed: sip_core::Fixed,
        before: Option<Before>,
        read: Vec<Fmt>,
        out: Mutex<(i32, Vec<String>)>,
    }
    impl RouteRunner for Call {
        fn run_failure(&self, _: usize, _: &mut Ctx<'_, '_>) {}
        fn run_onreply(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_branch(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_event(&self, _: usize, ctx: &mut Ctx<'_, '_>) -> bool {
            if let Some(b) = &self.before {
                b(ctx);
            }
            let rc = (self.func)(ctx, &*self.fixed);
            let read = self.read.iter().map(|f| f.eval(ctx)).collect();
            *lock(&self.out) = (rc, read);
            true
        }
    }

    fn registry(name: &'static str) -> Registry {
        let mut reg = Registry::default();
        reg.load(Arc::new(sip_core::corefns::CoreModule)).unwrap();
        reg.load(Arc::new(Jansson::named(name))).unwrap();
        reg
    }

    fn arg(reg: &Registry, s: &str) -> Arg {
        let f = parse_fmt(s, reg.pvs()).unwrap();
        if f.has_pv() { Arg::Fmt(Arc::new(f)) } else { Arg::Str(f.literal()) }
    }

    /// Runs `name(args)` with `$var(doc)` set to `doc`; returns the result
    /// code, `$var(out)` and `$var(doc)` afterwards.
    fn run_with(module: &'static str, name: &str, args: &[&str], doc: Option<&str>, before: Option<Before>) -> (i32, String, String) {
        let reg = registry(module);
        let e = reg.get(name).unwrap();
        let args: Vec<Arg> = args.iter().map(|a| arg(&reg, a)).collect();
        let doc_pv = parse_fmt("$var(doc)", reg.pvs()).unwrap().single_pv().cloned().unwrap();
        let doc = doc.map(str::to_string);
        let before: Option<Before> = match (doc, before) {
            (Some(d), None) => Some(Box::new(move |ctx: &mut Ctx<'_, '_>| doc_pv.set(ctx, Val::Str(d.clone())).unwrap())),
            (None, b) => b,
            (Some(_), Some(_)) => panic!("either a document or a setup closure"),
        };
        let read = vec![parse_fmt("$var(out)", reg.pvs()).unwrap(), parse_fmt("$var(doc)", reg.pvs()).unwrap()];
        let call = Arc::new(Call { func: e.func.clone(), fixed: (e.fixup)(&args).unwrap(), before, read, out: Mutex::new((i32::MIN, vec![])) });
        let hub = RouteHub::default();
        hub.set_names(RouteNames { event: vec!["call".into()], ..Default::default() });
        hub.set_runner(call.clone());
        hub.run_event_with("call", &NoNet, None, |_| {});
        let (rc, read) = lock(&call.out).clone();
        (rc, read[0].clone(), read[1].clone())
    }

    fn run(name: &str, args: &[&str], doc: Option<&str>) -> (i32, String, String) {
        run_with("jansson", name, args, doc, None)
    }

    const DOC: &str = r#"{"a":{"b":[1,{"c":"x"}],"n":-7,"f":1.5,"t":true,"z":null},"s":"str","0":"zero","e":[]}"#;

    #[test]
    fn jansson_get_follows_paths() {
        let cases: &[(&str, i32, &str)] = &[
            ("s", 1, "str"),
            ("a.n", 1, "-7"),
            ("a.f", 1, "1.5"),
            ("a.t", 1, "1"),
            ("a.b[0]", 1, "1"),
            ("a.b.0", 1, "1"),
            ("a.b[1].c", 1, "x"),
            ("a.b[1]", 1, r#"{"c":"x"}"#),
            ("e", 1, "[]"),
            ("0", 1, "zero"),
            ("a.b[2]", -1, ""),
            ("a.missing", -1, ""),
            ("s.x", -1, ""),
        ];
        for &(path, rc, out) in cases {
            let (got_rc, got, _) = run("jansson_get", &[path, DOC, "$var(out)"], None);
            assert_eq!((got_rc, got.as_str()), (rc, out), "{path}");
        }
        assert_eq!(
            run("jansson_get", &["", DOC, "$var(out)"], None).1,
            serde_json::from_str::<Value>(DOC).unwrap().to_string(),
            "the empty path is the document"
        );
        assert_eq!(run("jansson_get", &["a", "not json", "$var(out)"], None).0, -1);
    }

    #[test]
    fn jansson_get_of_null_sets_null() {
        let (rc, out, _) = run("jansson_get", &["a.z", DOC, "$var(out)"], None);
        assert_eq!((rc, out.as_str()), (1, ""));
    }

    #[test]
    fn jansson_array_size_counts_arrays_only() {
        let cases: &[(&str, i32, &str)] = &[("a.b", 1, "2"), ("e", 1, "0"), ("s", -1, ""), ("a", -1, ""), ("nope", -1, "")];
        for &(path, rc, out) in cases {
            let (got_rc, got, _) = run("jansson_array_size", &[path, DOC, "$var(out)"], None);
            assert_eq!((got_rc, got.as_str()), (rc, out), "{path}");
        }
    }

    #[test]
    fn jansson_get_field_reads_top_level_keys_only() {
        for module in ["jansson", "json"] {
            let name = if module == "json" { "json_get_field" } else { "jansson_get_field" };
            let (rc, out, _) = run_with(module, name, &[DOC, "s", "$var(out)"], None, None);
            assert_eq!((rc, out.as_str()), (1, "str"));
            assert_eq!(run_with(module, name, &[DOC, "a.n", "$var(out)"], None, None).0, -1, "not a path");
        }
        assert!(registry("json").get("jansson_get").is_none(), "json has only json_get_field");
    }

    #[test]
    fn jansson_set_builds_documents() {
        // (type, path, value, document before, result, document after)
        type Case<'a> = (&'a str, &'a str, &'a str, Option<&'a str>, i32, &'a str);
        let cases: &[Case] = &[
            ("string", "a", "x", None, 1, r#"{"a":"x"}"#),
            ("integer", "a.b", " 42 ", None, 1, r#"{"a":{"b":42}}"#),
            ("real", "r", "1.5", None, 1, r#"{"r":1.5}"#),
            ("true", "t", "ignored", None, 1, r#"{"t":true}"#),
            ("false", "t", "", None, 1, r#"{"t":false}"#),
            ("null", "n", "", None, 1, r#"{"n":null}"#),
            ("object", "o", r#"{"k":[1]}"#, None, 1, r#"{"o":{"k":[1]}}"#),
            ("array", "l[1]", "[2]", None, 1, r#"{"l":[null,[2]]}"#),
            ("STRING", "a", "y", Some(r#"{"a":"x","b":1}"#), 1, r#"{"a":"y","b":1}"#),
            ("string", "b.c", "v", Some(r#"{"b":5}"#), 1, r#"{"b":{"c":"v"}}"#),
            ("string", "a", "v", Some("not json"), 1, r#"{"a":"v"}"#),
            ("integer", "a", "x1", Some(r#"{"a":1}"#), -1, r#"{"a":1}"#),
            ("real", "a", "nan?", None, -1, ""),
            ("object", "a", "{", None, -1, ""),
            ("decimal", "a", "1", None, -1, ""),
            ("string", "l.99999999", "x", None, -1, ""),
        ];
        for &(ty, path, value, before, rc, after) in cases {
            let (got_rc, _, doc) = run("jansson_set", &[ty, path, value, "$var(doc)"], before);
            assert_eq!((got_rc, doc.as_str()), (rc, after), "{ty} {path} {value:?} on {before:?}");
        }
    }

    #[test]
    fn jansson_append_creates_or_extends_arrays() {
        let cases: &[(&str, &str, Option<&str>, &str)] = &[
            ("l", "1", None, r#"{"l":[1]}"#),
            ("l", "2", Some(r#"{"l":[1]}"#), r#"{"l":[1,2]}"#),
            ("l", "2", Some(r#"{"l":"scalar"}"#), r#"{"l":[2]}"#),
            ("a.l", "3", Some(r#"{"x":0}"#), r#"{"a":{"l":[3]},"x":0}"#),
        ];
        for &(path, value, before, after) in cases {
            let (rc, _, doc) = run("jansson_append", &["integer", path, value, "$var(doc)"], before);
            assert_eq!((rc, doc.as_str()), (1, after), "{path} on {before:?}");
        }
    }

    #[test]
    fn set_then_get_round_trips() {
        for (ty, value, back) in [("string", "a b", "a b"), ("integer", "-3", "-3"), ("true", "", "1"), ("object", r#"{"x":1}"#, r#"{"x":1}"#)] {
            let (_, _, doc) = run("jansson_set", &[ty, "p.q[2]", value, "$var(doc)"], None);
            let (rc, out, _) = run("jansson_get", &["p.q[2]", &doc, "$var(out)"], None);
            assert_eq!((rc, out.as_str()), (1, back), "{ty}");
        }
    }

    #[test]
    fn xdecode_and_xencode() {
        let decode = |json: &'static str| {
            Box::new(move |ctx: &mut Ctx<'_, '_>| {
                let v = parse(json).unwrap();
                let objs: Vec<HashMap<String, Val>> = match &v {
                    Value::Object(o) => vec![o.iter().map(|(k, v)| (k.clone(), to_val(v))).collect()],
                    _ => vec![],
                };
                ctx.ext_mut::<TxnVars>().xavps.insert("x".into(), objs);
            }) as Before
        };
        let (rc, out, _) = run_with("jansson", "jansson_xencode", &["x", "$var(out)"], None, Some(decode(r#"{"b":"two","a":1,"n":null}"#)));
        assert_eq!((rc, out.as_str()), (1, r#"{"a":1,"b":"two","n":null}"#), "sorted keys");
        assert_eq!(run("jansson_xencode", &["none", "$var(out)"], None).0, -1);
        // "$xavp(x)" works as well as the bare name.
        let (rc, out, _) = run_with("jansson", "jansson_xencode", &["$xavp(x)", "$var(out)"], None, Some(decode(r#"{"a":1}"#)));
        assert_eq!((rc, out.as_str()), (1, r#"{"a":1}"#));
        // xdecode then xencode: an array of objects gives one item each, in order.
        let xdecode = |json: &str| {
            let reg = registry("jansson");
            let e = reg.get("jansson_xdecode").unwrap();
            let (func, fixed) = (e.func.clone(), (e.fixup)(&[Arg::Str(json.into()), Arg::Str("x".into())]).unwrap());
            Box::new(move |ctx: &mut Ctx<'_, '_>| assert_eq!(func(ctx, &*fixed), 1)) as Before
        };
        let (rc, out, _) = run_with("jansson", "jansson_xencode", &["x", "$var(out)"], None, Some(xdecode(r#"[{"a":1,"t":true},2,{"b":"x"}]"#)));
        assert_eq!((rc, out.as_str()), (1, r#"{"a":1,"t":1}"#), "the first item; booleans become integers");
        let (_, out, _) = run_with("jansson", "jansson_xencode", &["x", "$var(out)"], None, Some(xdecode(r#"{"o":{"k":1}}"#)));
        assert_eq!(out, r#"{"o":"{\"k\":1}"}"#, "nested values are kept as JSON text");
        assert_eq!(run("jansson_xdecode", &["5", "x"], None).0, -1, "not an object or array");
        assert_eq!(run("jansson_xdecode", &["{", "x"], None).0, -1);
    }

    #[test]
    fn outputs_must_be_variables() {
        let reg = registry("jansson");
        let f = reg.get("jansson_get").unwrap();
        assert!((f.fixup)(&[Arg::Str("a".into()), Arg::Str("{}".into()), Arg::Str("out".into())]).is_err());
        assert!((f.fixup)(&[Arg::Str("a".into()), Arg::Str("{}".into())]).is_err());
    }
}
