//! Config check mode (`ferrosip -c`) is process-wide state, so it gets its
//! own test binary.

use sip_db::{DbError, connect, set_check_only};

#[test]
fn check_mode_validates_the_url_and_opens_nothing() {
    set_check_only(true);
    // Neither the directory, the file nor the servers exist: nothing is opened.
    for url in [
        "text:///nonexistent/ferrosip",
        "text:/x",
        "sqlite:///nonexistent/dir/x.db",
        "mysql://u:p@db.invalid/k",
        "postgres://u@db.invalid/k",
        "postgresql://h/k",
    ] {
        let db = connect(url).unwrap_or_else(|e| panic!("{url}: {e}"));
        assert!(db.query("t", &[], &[]).unwrap().rows.is_empty(), "{url}");
        assert_eq!(db.insert("t", &["a"], &["x".into()]), Ok(()), "{url}");
        assert_eq!(db.update("t", &[], &[("a", "y".into())]), Ok(0), "{url}");
        assert_eq!(db.delete("t", &[]), Ok(0), "{url}");
        assert!(db.raw("SELECT 1").unwrap().rows.is_empty(), "{url}");
    }
    for bad in ["", "redis://h", "mysql:/x", "postgres:x", "sqlite"] {
        assert!(matches!(connect(bad), Err(DbError::Config(m)) if m.contains("unsupported db_url")), "{bad:?}");
    }
    set_check_only(false);
    assert!(connect("text:///nonexistent/ferrosip").err().unwrap().is_conn(), "off again: the directory is checked");
}
