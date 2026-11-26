//! `dialplan` — number translation rules from the `dialplan` table
//! (`dpid, pr, match_op, match_exp, match_len, subst_exp, repl_exp, attrs`).
//!
//! Rules of a dialplan id are tried by ascending `pr`; the first whose
//! match succeeds (`match_op` 0 string equality, 1 regex, 2 fnmatch, with
//! `match_len` > 0 also requiring that input length) is applied: with a
//! `subst_exp` regex the first match is replaced by `repl_exp` (`\1`…
//! back-references), otherwise the input becomes `repl_exp` (or stays as
//! is if that is empty). Its `attrs` go to `attrs_pvar`.
//!
//! Functions: `dp_translate(id[, "src/dst"])` (default `$rU/$rU`),
//! `dp_match(id, input)`, `dp_replace(id, input, $dst)`. RPC:
//! `dialplan.reload`, `dialplan.dump <id>`, `dialplan.translate <id> <input>`.
//! As in Sipwise's build, a broken rule is skipped (logged), not fatal.

use crate::{args, fnmatch};
use regex::Regex;
use sip_core::module::{DynInt, DynStr, rc};
use sip_core::pv::{PvRef, Val, parse_pv};
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::serde_json::json;
use sip_core::sig::{FnSig, Param};
use sip_core::sync::{lock, read, write};
use sip_core::{Arg, Ctx, Module, Registry};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

#[derive(Clone, Debug)]
enum Match {
    Eq(String),
    Re(Regex),
    Glob(String),
}

#[derive(Clone, Debug)]
struct Rule {
    pr: i64,
    m: Match,
    match_len: usize,
    subst: Option<Regex>,
    repl: String,
    attrs: String,
    raw: (String, String, String),
}

type Plans = BTreeMap<i64, Vec<Rule>>;

pub struct Dialplan {
    db_url: Mutex<Option<String>>,
    table: Mutex<String>,
    attrs_pvar: Mutex<Option<String>>,
    attrs_pv: OnceLock<PvRef>,
    plans: RwLock<Arc<Plans>>,
}

impl Default for Dialplan {
    fn default() -> Self {
        Self {
            db_url: Mutex::new(None),
            table: Mutex::new("dialplan".into()),
            attrs_pvar: Mutex::new(None),
            attrs_pv: OnceLock::new(),
            plans: RwLock::new(Arc::new(BTreeMap::new())),
        }
    }
}

/// `\1` → `${1}` for the regex crate.
fn repl_syntax(r: &str) -> String {
    let mut o = String::with_capacity(r.len().saturating_add(8));
    let mut it = r.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\\' => match it.next_if(char::is_ascii_digit) {
                Some(d) => {
                    o.push_str("${");
                    o.push(d);
                    o.push('}');
                }
                None => o.push(c),
            },
            '$' => o.push_str("$$"),
            c => o.push(c),
        }
    }
    o
}

impl Rule {
    fn matches(&self, input: &str) -> bool {
        if self.match_len > 0 && input.len() != self.match_len {
            return false;
        }
        match &self.m {
            Match::Eq(s) => s == input,
            Match::Re(r) => r.is_match(input),
            Match::Glob(g) => fnmatch(g.as_bytes(), input.as_bytes()),
        }
    }

    fn apply(&self, input: &str) -> String {
        match &self.subst {
            Some(re) => re.replacen(input, 1, repl_syntax(&self.repl).as_str()).into_owned(),
            None if self.repl.is_empty() => input.to_string(),
            None => self.repl.clone(),
        }
    }
}

impl Dialplan {
    fn reload(&self) -> Result<usize, String> {
        let url = lock(&self.db_url).clone().unwrap_or_else(|| sip_db::default_url("dialplan"));
        let db = sip_db::connect(&url)?;
        let rows = db.query(&lock(&self.table), &["dpid", "pr", "match_op", "match_exp", "match_len", "subst_exp", "repl_exp", "attrs"], &[])?;
        let mut plans: Plans = BTreeMap::new();
        let mut n = 0usize;
        for r in rows.rows {
            let txt = |i: usize| r.get(i).map(sip_db::DbVal::text).unwrap_or_default();
            let int = |i: usize| r.get(i).and_then(sip_db::DbVal::int).unwrap_or(0);
            let (exp, subst) = (txt(3), txt(5));
            let m = match int(2) {
                0 => Ok(Match::Eq(exp.clone())),
                1 => Regex::new(&exp).map(Match::Re).map_err(|e| e.to_string()),
                2 => Ok(Match::Glob(exp.clone())),
                op => Err(format!("unknown match_op {op}")),
            };
            let sub = if subst.is_empty() { Ok(None) } else { Regex::new(&subst).map(Some).map_err(|e| e.to_string()) };
            match (m, sub) {
                (Ok(m), Ok(subst_re)) => {
                    plans.entry(int(0)).or_default().push(Rule {
                        pr: int(1),
                        m,
                        match_len: usize::try_from(int(4).max(0)).unwrap_or(usize::MAX),
                        subst: subst_re,
                        repl: txt(6),
                        attrs: txt(7),
                        raw: (exp, subst, txt(6)),
                    });
                    n = n.saturating_add(1);
                }
                (Err(e), _) | (_, Err(e)) => {
                    sip_core::log::log(sip_core::log::L_ERR, &format!("dialplan: skipping rule dpid={} pr={}: {e}", int(0), int(1)));
                }
            }
        }
        for rules in plans.values_mut() {
            rules.sort_by_key(|r| r.pr);
        }
        *write(&self.plans) = Arc::new(plans);
        Ok(n)
    }

    /// (output, attrs) of the first matching rule.
    fn translate(&self, id: i64, input: &str) -> Option<(String, String)> {
        let plans = read(&self.plans).clone();
        let r = plans.get(&id)?.iter().find(|r| r.matches(input))?;
        Some((r.apply(input), r.attrs.clone()))
    }

    fn set_attrs(&self, ctx: &mut Ctx<'_, '_>, attrs: &str) {
        if let Some(pv) = self.attrs_pv.get() {
            let _ = pv.set(ctx, Val::str(attrs));
        }
    }
}

impl Module for Dialplan {
    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, sig};
        const MATCH: &[Param] = &[arg("id", Int), arg("input", Str)];
        const REPLACE: &[Param] = &[arg("id", Int), arg("input", Str), arg("out", Var)];
        const ID: &[Param] = &[arg("id", Int)];
        Some(vec![
            sig("dp_translate", "translate", ID, Ret::Bool, "Translate the R-URI user with the rules of dialplan `id`"),
            sig("dp_match", "matches", MATCH, Ret::Bool, "`input` matches a rule of dialplan `id` (its attributes are set)"),
            sig("dp_replace", "replace", REPLACE, Ret::Bool, "Translate `input` with the rules of dialplan `id` into `out`"),
        ])
    }

    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("db_url", Ty::Str, "", "Database with the dialplan table"),
            p("table_name", Ty::Str, "dialplan", "Table of translation rules"),
            p("attrs_pvar", Ty::Str, "", "Variable that gets the matching rule's attrs"),
        ])
    }

    fn name(&self) -> &'static str {
        "dialplan"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "db_url" => *lock(&self.db_url) = Some(v.str()?.into()),
            "table_name" => *lock(&self.table) = v.str()?.into(),
            "attrs_pvar" => *lock(&self.attrs_pvar) = Some(v.str()?.into()),
            "fetch_rows" | "match_dynamic" | "append_branch" | "reload_delta" | "dpid_col" | "pr_col" | "match_op_col" | "match_exp_col" | "match_len_col"
            | "subst_exp_col" | "repl_exp_col" | "attrs_col" => {}
            _ => return Err(format!("dialplan: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        self.reload()?;
        if let Some(p) = lock(&self.attrs_pvar).clone() {
            let _ = self.attrs_pv.set(parse_pv(&p, reg.pvs())?);
        }
        let m = "dialplan";
        let me = self.clone();
        reg.export(
            m,
            "dp_translate",
            |a: &[Arg]| -> Result<(DynInt, PvRef, PvRef), String> {
                use sip_core::pv::FmtPart;
                let (id, src, dst) = match a {
                    [id] => (id, PvLater::parse("$rU")?, PvLater::parse("$rU")?),
                    // "$var(a)/$var(b)" arrives as a template: variable, "/", variable.
                    [id, Arg::Fmt(f)] => match f.0.as_slice() {
                        [FmtPart::Pv(x), FmtPart::Lit(sep), FmtPart::Pv(y)] if sep.trim() == "/" => (id, x.clone(), y.clone()),
                        _ => return Err("expected \"$src/$dst\" (two variables)".into()),
                    },
                    [_, _] => return Err("expected \"$src/$dst\" (two variables)".into()),
                    _ => return Err("expected id[, \"src/dst\"]".into()),
                };
                Ok((id.dyn_int()?, src, dst))
            },
            move |ctx: &mut Ctx, (id, src, dst): &(DynInt, PvRef, PvRef)| {
                let Some(id) = id.eval(ctx) else { return -1 };
                let input = src.get(ctx).as_str().into_owned();
                match me.translate(id, &input) {
                    Some((out, attrs)) => {
                        me.set_attrs(ctx, &attrs);
                        rc(dst.set(ctx, Val::Str(out)).is_ok())
                    }
                    None => -1,
                }
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "dp_match",
            |a: &[Arg]| {
                let [id, input] = args(a)?;
                Ok((id.dyn_int()?, input.dyn_str()?))
            },
            move |ctx: &mut Ctx, (id, input): &(DynInt, DynStr)| {
                let Some(id) = id.eval(ctx) else { return -1 };
                let input = input.eval(ctx).into_owned();
                match me.translate(id, &input) {
                    Some((_, attrs)) => {
                        me.set_attrs(ctx, &attrs);
                        1
                    }
                    None => -1,
                }
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "dp_replace",
            |a: &[Arg]| -> Result<(DynInt, DynStr, PvRef), String> {
                let [id, input, out] = args(a)?;
                let out = match out {
                    Arg::Fmt(f) => f.single_pv().cloned().ok_or("expected a variable")?,
                    _ => return Err("expected a variable".into()),
                };
                Ok((id.dyn_int()?, input.dyn_str()?, out))
            },
            move |ctx: &mut Ctx, (id, input, out): &(DynInt, DynStr, PvRef)| {
                let Some(id) = id.eval(ctx) else { return -1 };
                let input = input.eval(ctx).into_owned();
                match me.translate(id, &input) {
                    Some((o, attrs)) => {
                        me.set_attrs(ctx, &attrs);
                        rc(out.set(ctx, Val::Str(o)).is_ok())
                    }
                    None => -1,
                }
            },
        );
        let me = self.clone();
        reg.rpc.add("dialplan.reload", "Reload the dialplan table", move |_| me.reload().map(|n| json!(n)));
        let me = self.clone();
        reg.rpc.add("dialplan.dump", "dialplan.dump <dpid>", move |p| {
            let id = sip_core::rpc::int_param(p, 0)?;
            let plans = read(&me.plans).clone();
            let rules = plans.get(&id).ok_or("no such dialplan")?;
            Ok(json!(rules
                .iter()
                .map(|r| json!({"PRIORITY": r.pr, "MATCH EXPR": r.raw.0, "MATCH LEN": r.match_len, "SUBST EXPR": r.raw.1, "REPLACE EXPR": r.raw.2, "ATTRS": r.attrs}))
                .collect::<Vec<_>>()))
        });
        let me = self.clone();
        reg.rpc.add("dialplan.translate", "dialplan.translate <dpid> <input>", move |p| {
            let id = sip_core::rpc::int_param(p, 0)?;
            let input = sip_core::rpc::str_param(p, 1)?;
            let (out, attrs) = me.translate(id, &input).ok_or("no rule matched")?;
            Ok(json!({"Output": out, "Attributes": attrs}))
        });
        // Resolve the deferred `src/dst` variables now that all are registered.
        PvLater::bind(reg.pvs());
        Ok(())
    }
}

/// `dp_translate`'s "src/dst" variables are parsed against the core table,
/// which every variable it may name ($rU, $ru, $var, $avp…) lives in.
struct PvLater;

impl PvLater {
    fn table() -> &'static OnceLock<sip_core::pv::PvTable> {
        static T: OnceLock<sip_core::pv::PvTable> = OnceLock::new();
        &T
    }
    fn bind(t: &sip_core::pv::PvTable) {
        let _ = Self::table().set(t.clone());
    }
    fn parse(s: &str) -> Result<PvRef, String> {
        let t = Self::table().get().ok_or("dialplan: variables not ready")?;
        parse_pv(s.trim(), t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        let r = Rule {
            pr: 0,
            m: Match::Re(Regex::new("^0([1-9][0-9]+)$").unwrap()),
            match_len: 0,
            subst: Some(Regex::new("^0([1-9][0-9]+)$").unwrap()),
            repl: "+49\\1".into(),
            attrs: "de".into(),
            raw: Default::default(),
        };
        assert!(r.matches("03012345"));
        assert_eq!(r.apply("03012345"), "+493012345");
        assert_eq!(repl_syntax("a$\\2"), "a$$${2}");
    }

    fn mk(pr: i64, m: Match, match_len: usize, subst: Option<&str>, repl: &str, attrs: &str) -> Rule {
        Rule { pr, m, match_len, subst: subst.map(|s| Regex::new(s).unwrap()), repl: repl.into(), attrs: attrs.into(), raw: Default::default() }
    }

    fn re(s: &str) -> Match {
        Match::Re(Regex::new(s).unwrap())
    }

    #[test]
    fn dialplan_match_operators_and_length() {
        let cases = [
            (Match::Eq("110".into()), 0, "110", true),
            (Match::Eq("110".into()), 0, "1100", false),
            (Match::Eq("".into()), 0, "", true),
            (re("^0[1-9]"), 0, "0301", true),
            (re("^0[1-9]"), 0, "0030", false),
            (re("1"), 0, "x1x", true),
            (Match::Glob("49*".into()), 0, "4930", true),
            (Match::Glob("49*".into()), 0, "4", false),
            (Match::Glob("0?[!0]".into()), 0, "012", true),
            (Match::Glob("0?[!0]".into()), 0, "010", false),
            (Match::Glob("*".into()), 3, "123", true),
            (Match::Glob("*".into()), 3, "1234", false),
            (re("^1"), 4, "123", false),
            (Match::Eq("123".into()), 2, "123", false),
        ];
        for (m, len, input, want) in cases {
            let what = format!("{m:?} len {len}");
            assert_eq!(mk(0, m, len, None, "", "").matches(input), want, "{what} on {input:?}");
        }
    }

    #[test]
    fn dialplan_substitution_and_replacement() {
        let cases = [
            // (subst, repl, input, output)
            (Some("^00"), "+", "004930", "+4930"),
            (Some("^0([1-9])"), r"+49\1", "0301", "+49301"),
            (Some("([0-9])([0-9])"), r"\2\1", "1234", "2134"),
            (Some("x"), "y", "123", "123"),
            (Some("^(.*)$"), r"$1-\1", "ab", "$1-ab"),
            (Some("^1"), "", "123", "23"),
            (Some("^(1)"), r"\9", "123", "23"),
            (None, "", "123", "123"),
            (None, "fixed", "123", "fixed"),
        ];
        for (subst, repl, input, want) in cases {
            assert_eq!(mk(0, re("."), 0, subst, repl, "").apply(input), want, "{subst:?} → {repl:?} on {input:?}");
        }
    }

    #[test]
    fn dialplan_back_reference_syntax() {
        let cases = [(r"\1", "${1}"), (r"\12", "${1}2"), (r"a\", r"a\"), (r"\a", r"\a"), ("$x", "$$x"), ("", ""), (r"\0", "${0}")];
        for (from, want) in cases {
            assert_eq!(repl_syntax(from), want, "{from:?}");
        }
    }

    #[test]
    fn dialplan_first_matching_rule_by_priority_wins() {
        let d = Dialplan::default();
        let mut plans = Plans::new();
        plans.insert(
            1,
            vec![
                mk(1, Match::Eq("112".into()), 0, None, "", "emergency"),
                mk(2, re("^0[1-9]"), 0, Some("^0"), "+49", "national"),
                mk(3, Match::Glob("*".into()), 0, None, "", "any"),
            ],
        );
        plans.insert(2, vec![mk(0, re("^9"), 0, None, "x", "")]);
        *write(&d.plans) = Arc::new(plans);
        let t = |id: i64, input: &str| d.translate(id, input);
        let s = |a: &str, b: &str| Some((a.to_string(), b.to_string()));
        assert_eq!(t(1, "112"), s("112", "emergency"));
        assert_eq!(t(1, "0301"), s("+49301", "national"));
        assert_eq!(t(1, "555"), s("555", "any"));
        assert_eq!(t(2, "555"), None, "no rule matches");
        assert_eq!(t(2, "9"), s("x", ""));
        assert_eq!(t(3, "9"), None, "unknown dialplan");
    }

    #[test]
    fn dialplan_parameters() {
        let d = Dialplan::default();
        assert!(d.set_param("match_dynamic", &Arg::Int(1)).is_ok());
        assert!(d.set_param("bogus", &Arg::Int(1)).is_err());
        d.set_param("table_name", &Arg::Str("dp".into())).unwrap();
        assert_eq!(*lock(&d.table), "dp");
    }

    use crate::testutil::{FakeNet, TextDir, call, fixup_err, fmt, registry, request, rpc, udp, with_ctx};
    use sip_core::serde_json::json;

    const HDR: &str = "dpid(int) pr(int) match_op(int) match_exp(string) match_len(int) subst_exp(string) repl_exp(string) attrs(string)\n";

    /// Dialplan 1: "112" as is, 0… → +49…, any three characters; dialplan
    /// 2: "y" → "z", and three broken rules that are skipped.
    fn registered() -> (TextDir, Arc<Dialplan>, Registry) {
        let dir = TextDir::new(&[(
            "dialplan",
            &format!(
                "{HDR}1:1:1:^0([1-9]+)$:0:^0([1-9]+)$:+49\\\\1:national\n1:0:0:112:0:::emergency\n1:9:2:*:3:::three\n\
2:0:3:x:0:::\n2:1:1:(:0:::\n2:2:0:x:0:(::\n2:3:0:y:0::z:yy\n"
            ),
        )]);
        let d = Arc::new(Dialplan::default());
        d.set_param("db_url", &Arg::Str(dir.url())).unwrap();
        d.set_param("attrs_pvar", &Arg::Str("$avp(dpattrs)".into())).unwrap();
        let (mut reg, _) = registry();
        reg.load(d.clone()).unwrap();
        (dir, d, reg)
    }

    fn pv(reg: &Registry, ctx: &mut Ctx<'_, '_>, name: &str) -> String {
        parse_pv(name, reg.pvs()).unwrap().get(ctx).as_str().into_owned()
    }

    #[test]
    fn dialplan_reload_skips_broken_rules() {
        let (_dir, d, reg) = registered();
        let plans = read(&d.plans).clone();
        let prs: Vec<(i64, Vec<i64>)> = plans.iter().map(|(id, r)| (*id, r.iter().map(|r| r.pr).collect())).collect();
        assert_eq!(prs, [(1, vec![0, 1, 9]), (2, vec![3])], "unknown match_op, bad match and bad subst regex skipped; sorted by pr");
        assert_eq!(rpc(&reg, "dialplan.reload", json!([])).unwrap(), json!(4));
        assert_eq!(
            rpc(&reg, "dialplan.dump", json!([1])).unwrap()[1],
            json!({"PRIORITY": 1, "MATCH EXPR": "^0([1-9]+)$", "MATCH LEN": 0, "SUBST EXPR": "^0([1-9]+)$", "REPLACE EXPR": "+49\\1", "ATTRS": "national"})
        );
        assert_eq!(rpc(&reg, "dialplan.dump", json!([5])).unwrap_err(), "no such dialplan");
        assert_eq!(rpc(&reg, "dialplan.translate", json!([1, "0351"])).unwrap(), json!({"Output": "+49351", "Attributes": "national"}));
        assert_eq!(rpc(&reg, "dialplan.translate", json!([2, "0301"])).unwrap_err(), "no rule matched");
    }

    #[test]
    fn dialplan_script_functions() {
        let (_dir, _d, reg) = registered();
        let net = FakeNet(None);
        with_ctx(&request("INVITE", "sip:0351@x.example", ""), udp("192.0.2.1:5060"), &net, |ctx| {
            assert_eq!(call(&reg, ctx, "dp_translate", &[Arg::Int(1)]), 1);
            assert_eq!((pv(&reg, ctx, "$rU"), pv(&reg, ctx, "$avp(dpattrs)")), ("+49351".to_string(), "national".to_string()));
            parse_pv("$var(in)", reg.pvs()).unwrap().set(ctx, Val::str("112")).unwrap();
            assert_eq!(call(&reg, ctx, "dp_translate", &[Arg::Int(1), fmt(&reg, "$var(in) / $var(out)")]), 1);
            assert_eq!((pv(&reg, ctx, "$var(out)"), pv(&reg, ctx, "$avp(dpattrs)")), ("112".to_string(), "emergency".to_string()));
            assert_eq!(call(&reg, ctx, "dp_translate", &[Arg::Int(2)]), -1, "no rule matches +49351");
            assert_eq!(call(&reg, ctx, "dp_translate", &[fmt(&reg, "$fU")]), -1, "the id is not a number");

            assert_eq!(call(&reg, ctx, "dp_match", &[Arg::Int(1), Arg::Str("555".into())]), 1);
            assert_eq!(pv(&reg, ctx, "$avp(dpattrs)"), "three");
            assert_eq!(call(&reg, ctx, "dp_match", &[Arg::Int(1), Arg::Str("5555".into())]), -1);
            assert_eq!(call(&reg, ctx, "dp_match", &[fmt(&reg, "$fU"), Arg::Str("555".into())]), -1);

            assert_eq!(call(&reg, ctx, "dp_replace", &[Arg::Int(2), Arg::Str("y".into()), fmt(&reg, "$var(r)")]), 1);
            assert_eq!((pv(&reg, ctx, "$var(r)"), pv(&reg, ctx, "$avp(dpattrs)")), ("z".to_string(), "yy".to_string()));
            assert_eq!(call(&reg, ctx, "dp_replace", &[Arg::Int(2), Arg::Str("n".into()), fmt(&reg, "$var(r)")]), -1);
            assert_eq!(call(&reg, ctx, "dp_replace", &[fmt(&reg, "$fU"), Arg::Str("y".into()), fmt(&reg, "$var(r)")]), -1);
        });
        let cases: &[(&str, Vec<Arg>, &str)] = &[
            ("dp_translate", vec![Arg::Int(1), Arg::Str("$a/$b".into())], "expected \"$src/$dst\" (two variables)"),
            ("dp_translate", vec![Arg::Int(1), fmt(&reg, "$var(a)-$var(b)")], "expected \"$src/$dst\" (two variables)"),
            ("dp_translate", vec![], "expected id[, \"src/dst\"]"),
            ("dp_replace", vec![Arg::Int(1), Arg::Str("x".into()), Arg::Str("out".into())], "expected a variable"),
            ("dp_replace", vec![Arg::Int(1), Arg::Str("x".into()), fmt(&reg, "a$var(x)")], "expected a variable"),
        ];
        for (f, args, want) in cases {
            assert_eq!(fixup_err(&reg, f, args).as_deref(), Some(*want), "{f}{args:?}");
        }
    }
}
