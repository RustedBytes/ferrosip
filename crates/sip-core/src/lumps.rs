//! "Lumps": message edits recorded as (offset, delete-len, insert-bytes)
//! against the original receive buffer and applied in one pass at send time.
//! Same idea as Kamailio's data_lump.c / msg_translator.c — the message is
//! never re-serialised from a parsed model.

#[derive(Default)]
pub struct Lumps {
    /// In push order, so `truncate` removes exactly the edits added last.
    ops: Vec<Lump>,
    /// Scratch for `apply`: indices into `ops` in offset order (reused, so
    /// rendering doesn't allocate once warm).
    order: Vec<usize>,
}

struct Lump {
    at: usize,
    del: usize,
    ins: Vec<u8>,
}

impl Lumps {
    #[inline]
    pub fn clear(&mut self) {
        self.ops.clear();
    }
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
    pub fn len(&self) -> usize {
        self.ops.len()
    }
    /// Drop edits added after `len` (for temporary edits).
    pub fn truncate(&mut self, len: usize) {
        self.ops.truncate(len);
    }
    pub fn insert(&mut self, at: usize, data: impl Into<Vec<u8>>) {
        self.ops.push(Lump { at, del: 0, ins: data.into() });
    }
    pub fn delete(&mut self, at: usize, len: usize) {
        self.ops.push(Lump { at, del: len, ins: Vec::new() });
    }
    pub fn replace(&mut self, at: usize, len: usize, data: impl Into<Vec<u8>>) {
        self.ops.push(Lump { at, del: len, ins: data.into() });
    }

    /// Appends `buf` with all edits applied to `out`.
    /// Edits at the same offset keep their insertion order (stable sort).
    /// The edits themselves stay in push order (only an index is sorted), so
    /// `truncate(mark)` afterwards still removes the edits pushed after
    /// `mark`. Offsets and lengths past the end of `buf` are clipped.
    pub fn apply(&mut self, buf: &[u8], out: &mut Vec<u8>) {
        let Self { ops, order } = self;
        out.reserve(buf.len().saturating_add(256));
        order.clear();
        order.extend(0..ops.len());
        order.sort_by_key(|&i| ops.get(i).map(|l| l.at));
        let mut cur = 0;
        for l in order.iter().filter_map(|&i| ops.get(i)) {
            let at = l.at.min(buf.len());
            let end = at.saturating_add(l.del).min(buf.len());
            if at < cur {
                // Overlaps an earlier deletion: keep the insert, clip the delete.
                out.extend_from_slice(&l.ins);
                cur = cur.max(end);
                continue;
            }
            out.extend_from_slice(buf.get(cur..at).unwrap_or_default());
            out.extend_from_slice(&l.ins);
            cur = end;
        }
        out.extend_from_slice(buf.get(cur..).unwrap_or_default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn apply() {
        let buf = b"0123456789";
        let mut l = Lumps::default();
        l.delete(2, 3);
        l.insert(0, "A");
        l.replace(7, 1, "XYZ");
        l.insert(0, "B");
        let mut out = Vec::new();
        l.apply(buf, &mut out);
        assert_eq!(out, b"AB0156XYZ89");
    }

    #[test]
    fn truncate_after_apply_drops_the_temporary_edits() {
        // tm and Ctx::render_uri push temporary lumps (Via, R-URI) after the
        // script's own, render, then truncate back. apply() must leave the
        // lumps in insertion order, or truncate drops the wrong ones: the
        // script's header edit would vanish from the second fork branch, and
        // the first branch's R-URI rewrite stay behind.
        let buf = b"INVITE sip:a SIP/2.0\r\nX: 1\r\n\r\n";
        let mut l = Lumps::default();
        l.insert(28, "Added: yes\r\n"); // the script's append_hf (end of headers)
        let mark = l.len();
        for (uri, want) in [("sip:b", "INVITE sip:b"), ("sip:c", "INVITE sip:c")] {
            l.replace(7, 5, uri); // this branch's R-URI
            l.insert(22, "Via: v\r\n"); // this branch's Via
            let mut out = Vec::new();
            l.apply(buf, &mut out);
            l.truncate(mark);
            let s = String::from_utf8(out).unwrap();
            assert_eq!(s, format!("{want} SIP/2.0\r\nVia: v\r\nX: 1\r\nAdded: yes\r\n\r\n"));
        }
    }

    #[test]
    fn edits_past_the_end_are_clipped() {
        let buf = b"0123456789";
        let mut l = Lumps::default();
        l.delete(5, 3);
        l.replace(6, 50, "Z"); // overlaps the delete and runs past the end
        l.insert(40, "E"); // beyond the buffer
        let mut out = Vec::new();
        l.apply(buf, &mut out);
        assert_eq!(out, b"01234ZE");
    }

    fn render(l: &mut Lumps, buf: &[u8]) -> String {
        let mut out = Vec::new();
        l.apply(buf, &mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn overlapping_and_same_offset_edits() {
        type Edit = (usize, usize, &'static str);
        let cases: &[(&[Edit], &str)] = &[
            (&[], "0123456789"),
            (&[(0, 0, "")], "0123456789"),
            (&[(10, 0, "E")], "0123456789E"),
            (&[(0, 10, "")], ""),
            (&[(0, 10, "new")], "new"),
            (&[(3, 0, "a"), (3, 0, "b"), (3, 0, "c")], "012abc3456789"),
            // Replace then insert at the same offset: the insert follows the replacement.
            (&[(2, 3, "X"), (2, 0, "Y")], "01XY56789"),
            // Insert then replace at the same offset: push order.
            (&[(2, 0, "Y"), (2, 3, "X")], "01YX56789"),
            // Overlapping deletes remove the union.
            (&[(2, 4, ""), (4, 4, "")], "0189"),
            // A delete inside an earlier, larger one.
            (&[(1, 8, ""), (3, 2, "")], "09"),
            // An insert inside a deleted range is kept (after the earlier edit).
            (&[(1, 5, "R"), (3, 0, "I")], "0RI6789"),
            // Push order doesn't matter across offsets.
            (&[(8, 1, "h"), (1, 1, "b")], "0b234567h9"),
            // Adjacent edits do not overlap.
            (&[(2, 2, "x"), (4, 2, "y")], "01xy6789"),
        ];
        for (edits, want) in cases {
            let mut l = Lumps::default();
            for &(at, del, ins) in *edits {
                l.replace(at, del, ins);
            }
            assert_eq!(render(&mut l, b"0123456789"), *want, "{edits:?}");
            assert_eq!(l.len(), edits.len());
        }
    }

    #[test]
    fn apply_appends_and_can_run_twice() {
        let mut l = Lumps::default();
        l.insert(1, "+");
        let mut out = b"prev|".to_vec();
        l.apply(b"ab", &mut out);
        assert_eq!(out, b"prev|a+b", "apply appends to what is in out");
        assert_eq!(render(&mut l, b"ab"), "a+b", "rendering again gives the same result");
        l.clear();
        assert!(l.is_empty());
        assert_eq!(render(&mut l, b"ab"), "ab");
    }

    #[test]
    fn truncate_keeps_the_first_edits_in_push_order() {
        let mut l = Lumps::default();
        l.insert(5, "late");
        l.insert(0, "early");
        l.delete(1, 1);
        l.truncate(2);
        assert_eq!(render(&mut l, b"0123456789"), "early01234late56789");
        l.truncate(10);
        assert_eq!(l.len(), 2, "truncating past the end keeps everything");
        l.truncate(0);
        assert!(l.is_empty());
    }

    #[test]
    fn empty_buffer() {
        let mut l = Lumps::default();
        l.delete(0, 5);
        l.insert(3, "x");
        assert_eq!(render(&mut l, b""), "x");
    }
}
