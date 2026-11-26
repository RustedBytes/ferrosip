# sip-parser

This crate turns raw bytes from the network into a parsed
[SIP](../../docs/glossary.md#sip) message. Every other part of ferrosip that
reads SIP uses it. It is zero-copy and lazy: every parsed field is a slice
of the receive buffer, and a [header field](../../docs/glossary.md#header-field)
is parsed only when the caller asks for it.

It is the equivalent of [Kamailio's](../../docs/glossary.md#kamailio)
`src/core/parser/` directory (`msg_parser.c`, `parse_hname2.c`, `parse_via.c`,
`parse_uri.c`, `parse_nameaddr.c`, `contact/parse_contact.c`). It also
covers the stream framing of `tcp_read.c`.

It is the bottom of the dependency graph. It depends only on `bumpalo` and
`memchr`. These use it: `sip-core`, `sip-script`, `sip-transport`, almost
every `mod-*` crate, `tools/sipflood` and the fuzz targets. The crate is
`#![forbid(unsafe_code)]`.

## Contents

| File | Provides |
|---|---|
| `src/lib.rs` | `Msg` (first line + lazily parsed header index), `FirstLine`, `Method`, `Header`, `ParseError`; `stream_frame` / `Frame` for TCP/TLS framing |
| `src/hdr.rs` | `HdrKind`, the `HdrFlags` bitmask (≈ `hdr_flags_t` / `HDR_*_F`) and `kind_of` (header-name classification, compact forms included) |
| `src/via.rs` | `Via` and `parse_via`: transport, sent-by host/port, `branch`, `received`, `rport`, RFC 5923 `alias` |
| `src/uri.rs` | `Uri` / `parse_uri`, URI and header `param`, `name_addr`, `split_list` (top-level commas), `ContactSpec` / `parse_contact`, `parse_q` |
| `src/util.rs` | `trim`, `trim_start`, `split_host_port` (IPv6 brackets aware), `parse_u32` |

## Key types and APIs

### `Msg`

```rust
use bumpalo::Bump;
use sip_parser::{HdrFlags, HdrKind, Method, Msg, ParseError};

fn call_id(buf: &[u8]) -> Result<Option<Vec<u8>>, ParseError> {
    let arena = Bump::new();                 // per worker in ferrosip, reset per message
    let mut m = Msg::parse(buf, &arena)?;    // first line only
    if m.method() == Some(Method::Invite) {
        m.parse_headers(HdrFlags::VIA | HdrFlags::CALLID)?; // stops once both are seen
        let via = m.via1.as_ref();           // first Via, already parsed
        let _branch = via.and_then(|v| v.branch);
    }
    m.parse_headers(HdrFlags::CALLID)?;
    Ok(m.get(HdrKind::CallId).map(|h| h.body.to_vec()))
}
```

- `Msg::parse(buf, &arena)` parses only the first line. A request becomes
  `FirstLine::Request { method, method_raw, uri }`. A response becomes
  `FirstLine::Response { code, reason }`, with codes 100..699.
- `parse_headers(want)` parses header lines until every flag in `want` is
  set or the headers end. `HdrFlags::EOH` means "everything". Folded
  (continuation) lines are joined into one `Header`.
- Each `Header` has its `kind`, `name`, `body` (trimmed) and the
  `start`/`end` byte offsets of the whole line. In-place edits need those
  offsets.
- [Via](../../docs/glossary.md#via) handling: `via1` and `via2` are parsed
  as soon as they are seen. This holds even when both share one header
  line. `via1_next` is then the buffer offset of the second value.
  `via1_hdr` is the index of the header carrying `via1`.
- Accessors:
  - `is_request`, `method`, `status`, `ruri`, `ruri_user`;
  - `get(kind)`: the first header of that kind;
  - `body`;
  - `eoh_offset`: where new headers can be inserted (needs `EOH`);
  - `offset_of(slice)`: turns any parsed sub-slice back into a buffer
    offset.
- Errors: `ParseError::{Truncated, BadFirstLine, BadHeader(offset), BadVia}`.

`Method` covers `INVITE ACK BYE CANCEL REGISTER OPTIONS MESSAGE SUBSCRIBE
NOTIFY PUBLISH INFO UPDATE PRACK REFER`. Anything else is `Method::Other`,
and the raw name stays in `method_raw`. `Method::from_bytes` is an exact,
allocation-free byte match, so names are case-sensitive. `from_cseq` reads
the method of a [CSeq](../../docs/glossary.md#cseq) header body.
`as_str()` and `Display` give the name.

`HdrKind` names the headers the core cares about (`Via From To CallId CSeq
MaxForwards ContentLength Contact Route RecordRoute UserAgent`). Everything
else is `Other`, matched by name. `kind_of` dispatches on the name length
first. It recognises the compact forms `v f t i l m`.

### URIs, name-addr and Contact

```rust
use sip_parser::uri::{name_addr, parse_contact, split_list};
use sip_parser::parse_uri;

let u = parse_uri(b"sip:alice@example.com:5070;transport=tcp").unwrap();
assert_eq!(u.user, Some(&b"alice"[..]));
assert_eq!(u.port, Some(5070));
assert_eq!(u.param(b"transport"), Some(&b"tcp"[..]));

let (uri, params) = name_addr(b"\"Bob\" <sip:bob@x;lr>;tag=99");
assert_eq!((uri, params), (&b"sip:bob@x;lr"[..], &b"tag=99"[..]));

for c in split_list(b"<sip:a@b>;expires=60;q=0.5, *") {
    let spec = parse_contact(c); // star, uri, expires, q (thousandths), instance, reg_id
    let _ = spec;
}
```

- `Uri` is a parsed [SIP URI](../../docs/glossary.md#sip-uri). It holds:
  - `scheme`;
  - `user`, with the password stripped;
  - `host`, where IPv6 keeps its brackets;
  - `port`;
  - `params`: everything after the first `;`, without `?headers`.

  `is_sips()` and `param(name)` help. `param` returns `Some(b"")` for a
  flag.
- `name_addr` follows RFC 3261 §20. Without `<>`, parameters after the URI
  belong to the header, not the URI.
- `split_list` splits on commas that are not inside quotes or `<>`.
- `parse_contact` reads one [Contact](../../docs/glossary.md#contact)
  value. It extracts `expires`, `q`, `+sip.instance` (quotes removed) and
  `reg-id`. `q` goes through `parse_q`, so `0.5` becomes 500 (see
  [q-value](../../docs/glossary.md#q-value)). `Contact: *` sets `star`.

### Stream framing

On TCP and TLS, messages arrive as one byte stream. `stream_frame(buf, max_len)` looks for one message at the start of a read
buffer and returns a `Frame`:

| Result | Meaning |
|---|---|
| `Incomplete` | need more bytes |
| `Keepalive { len, ping }` | leading CR/LF; `ping` is the RFC 5626 double-CRLF ping that must be answered with one CRLF |
| `Message(len)` | a complete message (end of headers + Content-Length) |
| `Error(reason)` | headers or message larger than `max_len`, missing or bad Content-Length; the connection must be closed |

The ping is the [keepalive](../../docs/glossary.md#keepalive) of
[SIP Outbound](../../docs/glossary.md#sip-outbound). Content-Length is
mandatory on stream transports (RFC 3261 §18.3). A message without it is a
framing error.

## Design notes

- **Zero copy.** Every field is a `&'a [u8]` into the receive buffer. So
  `offset_of` gives positions for edits for free. `sip-core`'s
  [lumps](../../docs/glossary.md#lumps) rely on it.
- **Lazy.** `parse_headers` stops as soon as the requested headers are
  known. A relayed message never has its tail or body parsed. Parsed
  headers are remembered (`HdrFlags`), so asking again costs nothing.
- **Arena allocation.** The header index is the only per-message
  allocation. It is a `bumpalo` vector (initial capacity 16) in an arena
  the caller owns. `sip-transport` keeps one arena per
  [worker](../../docs/glossary.md#worker) and resets it after every
  message. This is the equivalent of Kamailio's per-process `pkg` memory.
- **Cheap name classification.** `kind_of` switches on the name length. It
  then compares case-insensitively only against the names of that length.
  `parse_hname2.c` does the same with 4-byte words.
- **No unsafe code.** The parser runs on untrusted bytes in every UDP
  worker and TCP reader, so it is also fuzzed (see below).

## Testing

- Unit tests: `cargo test -p sip-parser`. They cover:
  - lazy parsing stopping early;
  - a full parse with folded headers and multiple Vias per line;
  - responses and garbage input;
  - stream framing and keep-alives;
  - URIs including IPv6;
  - Contact lists with quoted commas, and q-values.
- Fuzz target: `fuzz/fuzz_targets/sip_msg.rs` runs `stream_frame`,
  `Msg::parse`, `parse_headers` and the URI / name-addr / Contact helpers
  on arbitrary bytes (`cd fuzz && cargo +nightly fuzz run sip_msg`).
- Every e2e suite in `tests/` exercises the parser indirectly.
  `tests/e2e_stream.py` covers stream framing (pipelining, keep-alives,
  limits).
