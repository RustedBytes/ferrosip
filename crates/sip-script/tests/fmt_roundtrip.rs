//! The formatter over every `.cfg` in the repository: formatting is
//! idempotent, and the configs ferrosip ships format at all.
#![allow(clippy::unwrap_used, reason = "test helpers outside #[test] fns")]

use std::path::{Path, PathBuf};

fn cfg_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if p.is_dir() && !matches!(name, "target" | "fuzz" | ".git" | "node_modules") {
            cfg_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "cfg") {
            out.push(p);
        }
    }
}

#[test]
fn formatting_is_idempotent_on_every_config_in_the_repository() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    for d in ["etc", "examples", "tests", "bench"] {
        cfg_files(&root.join(d), &mut files);
    }
    assert!(files.len() >= 10, "found {files:?}");
    let mut formatted = 0;
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap();
        let shipped = f.starts_with(root.join("etc")) || f.starts_with(root.join("examples"));
        let once = match sip_script::fmt::format(&src) {
            Ok(o) => o,
            // Some imported Kamailio samples use syntax ferrosip doesn't parse.
            Err(e) => {
                assert!(!shipped, "{}: {e}", f.display());
                continue;
            }
        };
        formatted += 1;
        assert_eq!(sip_script::fmt::format(&once).unwrap(), once, "{}: format(format(x)) != format(x)", f.display());
        assert!(once.ends_with('\n') && !once.ends_with("\n\n"), "{}: one final newline", f.display());
    }
    assert!(formatted >= 10, "only {formatted} of {} configs formatted", files.len());
}
