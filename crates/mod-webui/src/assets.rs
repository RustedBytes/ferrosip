//! The single-page app, embedded at build time from `assets/`
//! (built by `npm run build` in `ui/` and committed, so `cargo build`
//! needs no Node). JavaScript and CSS are stored gzip-compressed.

use std::sync::OnceLock;

pub struct Asset {
    pub path: &'static str,
    pub ctype: &'static str,
    pub bytes: &'static [u8],
    pub gzipped: bool,
    pub etag: String,
}

fn all() -> &'static [Asset] {
    static A: OnceLock<Vec<Asset>> = OnceLock::new();
    A.get_or_init(|| {
        let mk = |path, ctype, bytes: &'static [u8], gzipped| {
            let d = ring::digest::digest(&ring::digest::SHA256, bytes);
            let etag = format!("\"{}\"", d.as_ref().iter().take(12).map(|b| format!("{b:02x}")).collect::<String>());
            Asset { path, ctype, bytes, gzipped, etag }
        };
        vec![
            mk("/", "text/html; charset=utf-8", include_bytes!("../assets/index.html"), false),
            mk("/app.js", "text/javascript; charset=utf-8", include_bytes!("../assets/app.js.gz"), true),
            mk("/app.css", "text/css; charset=utf-8", include_bytes!("../assets/app.css.gz"), true),
            mk("/favicon.svg", "image/svg+xml", include_bytes!("../assets/favicon.svg"), false),
        ]
    })
}

pub fn find(path: &str) -> Option<&'static Asset> {
    let path = if path == "/index.html" { "/" } else { path };
    all().iter().find(|a| a.path == path)
}
