//! Bencode (rtpengine's "ng" control protocol).

use std::fmt::Write as _;

/// How deep lists and dictionaries may nest in decoded input.
pub const MAX_DEPTH: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum B {
    Int(i64),
    Str(Vec<u8>),
    List(Vec<B>),
    /// Keys in insertion order; sorted when encoding.
    Dict(Vec<(Vec<u8>, B)>),
}

impl B {
    pub fn s(v: impl AsRef<[u8]>) -> B {
        B::Str(v.as_ref().to_vec())
    }

    pub fn get(&self, k: &str) -> Option<&B> {
        match self {
            B::Dict(d) => d.iter().find(|(key, _)| key == k.as_bytes()).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn str(&self) -> Option<&[u8]> {
        match self {
            B::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            B::Int(i) => out.extend_from_slice(format!("i{i}e").as_bytes()),
            B::Str(s) => {
                out.extend_from_slice(format!("{}:", s.len()).as_bytes());
                out.extend_from_slice(s);
            }
            B::List(l) => {
                out.push(b'l');
                l.iter().for_each(|x| x.encode(out));
                out.push(b'e');
            }
            B::Dict(d) => {
                let mut d: Vec<&(Vec<u8>, B)> = d.iter().collect();
                d.sort_by(|a, b| a.0.cmp(&b.0));
                out.push(b'd');
                for (k, v) in d {
                    B::Str(k.clone()).encode(out);
                    v.encode(out);
                }
                out.push(b'e');
            }
        }
    }

    /// Decode one value; returns it and the rest. Lists and dictionaries
    /// nest at most [`MAX_DEPTH`] deep (the input comes from the network).
    pub fn decode(s: &[u8]) -> Option<(B, &[u8])> {
        Self::decode_at(s, 0)
    }

    fn decode_at(s: &[u8], depth: usize) -> Option<(B, &[u8])> {
        let (&tag, body) = s.split_first()?;
        match tag {
            b'i' => {
                let (num, rest) = split_on(body, b'e')?;
                Some((B::Int(std::str::from_utf8(num).ok()?.parse().ok()?), rest))
            }
            b'l' => {
                let depth = deeper(depth)?;
                let mut rest = body;
                let mut v = Vec::new();
                loop {
                    if let Some(after) = rest.strip_prefix(b"e") {
                        return Some((B::List(v), after));
                    }
                    let (x, r) = B::decode_at(rest, depth)?;
                    v.push(x);
                    rest = r;
                }
            }
            b'd' => {
                let depth = deeper(depth)?;
                let mut rest = body;
                let mut v = Vec::new();
                loop {
                    if let Some(after) = rest.strip_prefix(b"e") {
                        return Some((B::Dict(v), after));
                    }
                    let (B::Str(k), r) = B::decode_at(rest, depth)? else { return None };
                    let (x, r) = B::decode_at(r, depth)?;
                    v.push((k, x));
                    rest = r;
                }
            }
            b'0'..=b'9' => {
                let (len, rest) = split_on(s, b':')?;
                let n: usize = std::str::from_utf8(len).ok()?.parse().ok()?;
                // A huge length just doesn't fit (malformed peer input).
                let (body, rest) = rest.split_at_checked(n)?;
                Some((B::Str(body.to_vec()), rest))
            }
            _ => None,
        }
    }

    /// JSON-ish text (for `$rtpstat`, RPC).
    pub fn to_json(&self) -> String {
        let mut o = String::new();
        self.json_into(&mut o);
        o
    }

    fn json_into(&self, o: &mut String) {
        match self {
            B::Int(i) => {
                let _ = write!(o, "{i}");
            }
            B::Str(s) => json_str(s, o),
            B::List(l) => {
                o.push('[');
                for (i, x) in l.iter().enumerate() {
                    if i > 0 {
                        o.push(',');
                    }
                    x.json_into(o);
                }
                o.push(']');
            }
            B::Dict(d) => {
                o.push('{');
                for (i, (k, v)) in d.iter().enumerate() {
                    if i > 0 {
                        o.push(',');
                    }
                    json_str(k, o);
                    o.push(':');
                    v.json_into(o);
                }
                o.push('}');
            }
        }
    }
}

/// `s` as a JSON string (quoted and escaped; invalid UTF-8 replaced).
fn json_str(s: &[u8], o: &mut String) {
    o.push_str(&sip_core::serde_json::Value::from(String::from_utf8_lossy(s)).to_string());
}

/// The depth inside one more list or dictionary, if that is still allowed.
fn deeper(depth: usize) -> Option<usize> {
    depth.checked_add(1).filter(|&d| d <= MAX_DEPTH)
}

/// Split at the first `delim`: the bytes before and after it.
fn split_on(s: &[u8], delim: u8) -> Option<(&[u8], &[u8])> {
    let mut parts = s.splitn(2, |&c| c == delim);
    Some((parts.next()?, parts.next()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nesting_is_limited() {
        let nested = |n: usize| [vec![b'l'; n], vec![b'e'; n]].concat();
        assert!(B::decode(&nested(MAX_DEPTH)).is_some());
        assert!(B::decode(&nested(MAX_DEPTH + 1)).is_none());
        // Deep enough to overflow the stack without the limit.
        assert!(B::decode(&nested(1_000_000)).is_none());
        let dicts = [b"d1:a".repeat(MAX_DEPTH + 1), b"i1e".to_vec(), vec![b'e'; MAX_DEPTH + 1]].concat();
        assert!(B::decode(&dicts).is_none());
        let dicts = [b"d1:a".repeat(MAX_DEPTH), b"i1e".to_vec(), vec![b'e'; MAX_DEPTH]].concat();
        assert!(B::decode(&dicts).is_some());
    }

    #[test]
    fn roundtrip() {
        let d = B::Dict(vec![
            (b"sdp".to_vec(), B::s("v=0")),
            (b"command".to_vec(), B::s("offer")),
            (b"flags".to_vec(), B::List(vec![B::s("trust-address"), B::Int(3)])),
        ]);
        let mut out = Vec::new();
        d.encode(&mut out);
        assert_eq!(out, b"d7:command5:offer5:flagsl13:trust-addressi3ee3:sdp3:v=0e");
        let (back, rest) = B::decode(&out).unwrap();
        assert!(rest.is_empty());
        assert_eq!(back.get("command").and_then(B::str), Some(&b"offer"[..]));
        assert!(B::decode(b"d3:abc").is_none());
    }
}

#[cfg(test)]
mod fuzz_regressions {
    #[test]
    fn huge_string_length() {
        assert!(super::B::decode(b"18446744073709551615:x").is_none());
    }
}

#[cfg(test)]
mod table_tests {
    use super::*;

    fn enc(b: &B) -> Vec<u8> {
        let mut out = Vec::new();
        b.encode(&mut out);
        out
    }

    fn dict(entries: &[(&str, B)]) -> B {
        B::Dict(entries.iter().map(|(k, v)| (k.as_bytes().to_vec(), v.clone())).collect())
    }

    #[test]
    fn encode_exact_bytes() {
        let cases: &[(B, &[u8])] = &[
            (B::Int(0), b"i0e"),
            (B::Int(-42), b"i-42e"),
            (B::Int(i64::MAX), b"i9223372036854775807e"),
            (B::Int(i64::MIN), b"i-9223372036854775808e"),
            (B::s(""), b"0:"),
            (B::s("spam"), b"4:spam"),
            (B::Str(vec![0, 0xff, b':']), b"3:\x00\xff:"),
            (B::List(vec![]), b"le"),
            (B::List(vec![B::s("a"), B::Int(1), B::List(vec![])]), b"l1:ai1elee"),
            (B::Dict(vec![]), b"de"),
            (dict(&[("b", B::Int(2)), ("a", B::Int(1)), ("B", B::Int(0))]), b"d1:Bi0e1:ai1e1:bi2ee"),
            (dict(&[("ab", B::Int(2)), ("a", B::Int(1))]), b"d1:ai1e2:abi2ee"),
            (dict(&[("d", dict(&[("z", B::s("")), ("y", B::List(vec![]))]))]), b"d1:dd1:yle1:z0:ee"),
        ];
        for (b, want) in cases {
            assert_eq!(enc(b), *want, "{b:?}");
        }
    }

    #[test]
    fn decode_returns_the_value_and_the_rest() {
        let cases: &[(&[u8], B, &[u8])] = &[
            (b"i0e", B::Int(0), b""),
            (b"i-7eXYZ", B::Int(-7), b"XYZ"),
            (b"0:", B::s(""), b""),
            (b"3:abcdef", B::s("abc"), b"def"),
            (b"5:a:b:c", B::s("a:b:c"), b""),
            (b"lei1e", B::List(vec![]), b"i1e"),
            (b"l1:xi2ee", B::List(vec![B::s("x"), B::Int(2)]), b""),
            (b"d1:bi2e1:ai1ee", dict(&[("b", B::Int(2)), ("a", B::Int(1))]), b""),
            (b"d1:ad1:bl1:ceee", dict(&[("a", dict(&[("b", B::List(vec![B::s("c")]))]))]), b""),
        ];
        for (bytes, want, rest) in cases {
            assert_eq!(B::decode(bytes), Some((want.clone(), *rest)), "{:?}", String::from_utf8_lossy(bytes));
        }
    }

    #[test]
    fn decode_rejects_malformed_input() {
        let cases: &[&[u8]] = &[
            b"",
            b"x",
            b"e",
            b"i",
            b"i12",
            b"ie",
            b"i1.5e",
            b"iabce",
            b"i99999999999999999999e",
            b"4:abc",
            b"4abc",
            b"-1:a",
            b"l",
            b"li1e",
            b"l3:ab",
            b"d",
            b"d1:a",
            b"d1:ai1e",
            b"di1ei2ee",
            b"dlei1ee",
        ];
        for bytes in cases {
            assert_eq!(B::decode(bytes), None, "{:?}", String::from_utf8_lossy(bytes));
        }
    }

    #[test]
    fn decode_of_encode_is_identity_up_to_key_order() {
        let values = [
            B::Int(-1),
            B::s("v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\n"),
            B::List(vec![B::Int(1), B::s("two"), B::List(vec![B::Dict(vec![])])]),
            dict(&[("command", B::s("offer")), ("call-id", B::s("c@h")), ("flags", B::List(vec![B::s("trust-address")])), ("sdp", B::Str(vec![0xff; 3]))]),
        ];
        for v in values {
            let bytes = enc(&v);
            let (back, rest) = B::decode(&bytes).unwrap();
            assert!(rest.is_empty());
            let mut again = Vec::new();
            back.encode(&mut again);
            assert_eq!(again, bytes, "canonical form is stable");
            if let (B::Dict(a), B::Dict(b)) = (&v, &back) {
                let mut a = a.clone();
                a.sort_by(|x, y| x.0.cmp(&y.0));
                assert_eq!(&a, b, "keys come back sorted");
            } else {
                assert_eq!(back, v);
            }
        }
    }

    #[test]
    fn accessors() {
        let d = dict(&[("result", B::s("ok")), ("n", B::Int(1))]);
        assert_eq!(d.get("result").and_then(B::str), Some(&b"ok"[..]));
        assert_eq!(d.get("n").and_then(B::str), None);
        assert_eq!(d.get("missing"), None);
        assert_eq!(B::Int(1).get("n"), None);
        assert_eq!(B::s("x").str(), Some(&b"x"[..]));
    }

    #[test]
    fn to_json_is_valid_json() {
        let d = dict(&[
            ("result", B::s("ok")),
            ("totals", dict(&[("RTP", dict(&[("packets", B::Int(10))]))])),
            ("tags", B::List(vec![B::s("a\"b"), B::s("back\\slash"), B::s("ctl\u{1}\n"), B::Str(vec![0xff])])),
            ("k\"ey", B::Int(-1)),
        ]);
        let j = d.to_json();
        assert_eq!(
            j,
            r#"{"result":"ok","totals":{"RTP":{"packets":10}},"tags":["a\"b","back\\slash","ctl\u0001\n","�"],"k\"ey":-1}"#.replace("\\ufffd", "\u{fffd}")
        );
        let v: sip_core::serde_json::Value = sip_core::serde_json::from_str(&j).unwrap();
        assert_eq!(v["tags"][2], "ctl\u{1}\n");
        assert_eq!(B::List(vec![]).to_json(), "[]");
        assert_eq!(B::Dict(vec![]).to_json(), "{}");
    }
}
