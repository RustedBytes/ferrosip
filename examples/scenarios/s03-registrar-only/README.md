# s03-registrar-only (small)

This scenario models a [registrar](../../../docs/glossary.md#registrar)
and nothing else. Phones send [REGISTER](../../../docs/glossary.md#register)
to tell it where they can be reached. It proves that the registrar applies
the expiry limits and the contact limit, and that it handles refreshes,
removals and the [Path](../../../docs/glossary.md#path) header as RFC 3261
requires.

```
UA ──REGISTER──▶ ferrosip ── location.save() ──▶ location table
                 │ expiry: default 10m, min 30s (else 423), max 1h (capped)
                 │ max_contacts 3 (else 503), Path stored and echoed
                 │ anything else: 405 Allow: REGISTER
```

**Shows**:
- `location.save()` with the `[modules.location]` limits
  (`default_expires`, `min_expires`, `max_expires`, `max_contacts`,
  `use_path`). It writes to the
  [location table](../../../docs/glossary.md#location-service).
- `text.append_to_reply()` for the 405's Allow.
- The source check with `ip.in_subnet(msg.src.ip, …)`. It is also what
  keeps `register_without_auth` quiet: only the trusted network may
  register. s04 has the authenticated version.

**Edge cases checked** (`tests/scenarios/s03_registrar_only.py`):
- Expires 7200 is capped at 3600. No expiry at all gives
  `default_expires`. A [Contact](../../../docs/glossary.md#contact)
  `;expires=` wins over the Expires header.
- Expires 10 and `;expires=5` get `423` with `Min-Expires: 30`, and store
  nothing.
- A query REGISTER (no Contact) lists the bindings.
- `max_contacts`:
  - a REGISTER that would make 4 bindings gets 503 and stores none of its
    contacts;
  - the third binding and a refresh at the limit are accepted.
- Expires: 0 for one contact removes only that one. This also works mixed
  with a new contact in one REGISTER.
- A refresh on the same [Call-ID](../../../docs/glossary.md#call-id) with
  a higher [CSeq](../../../docs/glossary.md#cseq) updates the one binding.
  The same CSeq again (within [usrloc's](../../../docs/glossary.md#usrloc)
  `cseq_delay`) is a [retransmission](../../../docs/glossary.md#retransmission)
  that changes nothing. A lower one gets `400`.
- `Contact: *` is refused (400) with a non-zero Expires, with another
  contact, or without Expires. With `Expires: 0` it removes everything,
  checked by a query and `ul.lookup`.
- Path with `Supported: path` is echoed in the 200 and stored. Without
  `Supported: path` it is stored but not echoed (`path_mode` lazy).
- [OPTIONS](../../../docs/glossary.md#options) gets `405` with
  `Allow: REGISTER`.

**Run it by hand**: `ferrosip --config ferrosip.toml`. It listens on port
5060. Set `SIP_PORT`, `TRUSTED` to change them.
