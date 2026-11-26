#!/usr/bin/env python3
"""End-to-end checks for the production SQL drivers (Phase 11): the same
proxy runs against PostgreSQL (`postgres://`) and MariaDB/MySQL
(`mysql://`). Checked per backend:
- auth_db credentials from `subscriber`;
- usrloc `db_mode=1`, with the contact read back after a proxy restart;
- dispatcher sets from the db, plus `dispatcher.reload`;
- acc rows;
- sqlops (`sql_query`, `$dbr`, `sql_query_async`);
- reconnecting after the database server restarts.

Both servers are started here from scratch: the newest Postgres in
/usr/lib/postgresql, MariaDB from mariadbd. A backend whose server binary is
missing is skipped with a notice. Needs root (the servers run as the
postgres/root users). Run from the repo root after
`cargo build --release`.
"""
import glob, hashlib, json, os, re, shutil, subprocess, sys, tempfile, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_routing import Peer, first, hdr  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TLS = os.path.join(ROOT, "etc/tls")
PROXY, CALLER, UA, DS1, DS2 = 7300, 7399, 7301, 7311, 7312
PG_PORT, MY_PORT = 7343, 7344
SOCK = os.path.join(ROOT, "target/e2e_sqldb.sock")
# The newest installed PostgreSQL (Debian/Ubuntu layout); override with PGBIN.
PGBIN = os.environ.get("PGBIN") or max(glob.glob("/usr/lib/postgresql/*/bin"), key=lambda p: int(p.split("/")[-2]), default="")

CFG = f"""
loadmodule "tm"
loadmodule "sl"
loadmodule "textops"
loadmodule "usrloc"
loadmodule "registrar"
loadmodule "auth"
loadmodule "auth_db"
loadmodule "dispatcher"
loadmodule "acc"
loadmodule "sqlops"
modparam("tm", "fr_timer", 1000)
modparam("usrloc", "db_url", "URL")
modparam("usrloc", "db_mode", 1)
modparam("auth_db", "db_url", "URL")
modparam("auth_db", "calculate_ha1", 1)
modparam("auth_db", "load_credentials", "rpid")
modparam("dispatcher", "db_url", "URL")
modparam("acc", "db_url", "URL")
modparam("acc", "db_flag", 2)
modparam("acc", "db_extra", "src_user=$fU;dst_user=$rU")
modparam("sqlops", "sqlcon", "db=>URL")

request_route {{
    if (is_method("REGISTER")) {{
        if (!www_authorize("x", "subscriber")) {{ www_challenge("x", "0"); exit; }}
        append_to_reply("X-RPID: $avp(rpid)\\r\\n");
        save("location");
        exit;
    }}
    if ($rU == "ds") {{
        if (!ds_select_dst(1, 4)) {{ sl_send_reply(503, "no dst"); exit; }}
        t_relay();
        exit;
    }}
    if ($rU == "sql") {{
        sql_query("db", "select count(*) as n, max(username) as u from location", "r");
        sql_query("db", "update subscriber set rpid = 'changed' where username = 'alice'");
        $var(upd) = $rc;
        append_to_reply("X-SQL: $dbr(r=>rows) $dbr(r=>[0,0]) $dbr(r=>[0,1]) $dbr(r=>colname[1]) upd=$var(upd)\\r\\n");
        sl_send_reply(200, "SQL");
        exit;
    }}
    if ($rU == "async") {{
        sql_query_async("db", "insert into acc(method, from_tag, to_tag, callid, sip_code, sip_reason, time) values('X', 'f', 't', '$ci', '200', 'async', 0)");
        sl_send_reply(200, "queued");
        exit;
    }}
    if ($rU == "acc") {{
        setflag(2);
        t_relay("udp:127.0.0.1:{UA}");
        exit;
    }}
    if (lookup("location")) {{ t_relay(); exit; }}
    sl_send_reply(404, "Not Found");
}}
"""

failures = 0
seq = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def run(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=60, **kw)


# ------------------------------------------------------------- servers --
class Postgres:
    name = "postgres"

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="ferrosip-pg-")
        shutil.chown(self.dir, "postgres", "postgres")
        os.chmod(self.dir, 0o700)
        self.plain_url = f"postgres://postgres@127.0.0.1:{PG_PORT}/ferrosip"
        self.url = f"{self.plain_url}?sslmode=verify-full&sslrootcert={TLS}/ca.pem"

    @staticmethod
    def available():
        return os.path.exists(f"{PGBIN}/initdb")

    def pg(self, args):
        return run(["su", "postgres", "-c", args])

    def start(self, first=True):
        if first:
            r = self.pg(f"{PGBIN}/initdb -D {self.dir}/data -U postgres --auth=trust -E UTF8")
            if r.returncode:
                raise RuntimeError(r.stderr)
            # TLS required on TCP; the server certificate has IP:127.0.0.1.
            for src, dst in ((f"{TLS}/server.pem", "server.crt"), (f"{TLS}/server.key.pem", "server.key")):
                shutil.copy(src, f"{self.dir}/data/{dst}")
                shutil.chown(f"{self.dir}/data/{dst}", "postgres", "postgres")
                os.chmod(f"{self.dir}/data/{dst}", 0o600)
            with open(f"{self.dir}/data/postgresql.conf", "a") as f:
                f.write("ssl = on\nssl_cert_file = 'server.crt'\nssl_key_file = 'server.key'\n")
            with open(f"{self.dir}/data/pg_hba.conf", "w") as f:
                f.write("local all all trust\nhostssl all all 127.0.0.1/32 trust\nhostnossl all all 127.0.0.1/32 reject\n")
        r = self.pg(f"{PGBIN}/pg_ctl -D {self.dir}/data -w -l {self.dir}/log -o '-p {PG_PORT} -k {self.dir} -c listen_addresses=127.0.0.1' start")
        if r.returncode:
            raise RuntimeError(r.stderr + open(f"{self.dir}/log").read())
        if first:
            self.sql("create database ferrosip", db="postgres")
            r = run(["psql", "-q", "-h", "127.0.0.1", "-p", str(PG_PORT), "-U", "postgres", "-d", "ferrosip", "-v", "ON_ERROR_STOP=1", "-f", f"{ROOT}/etc/schema/postgres.sql"])
            if r.returncode:
                raise RuntimeError(r.stderr)

    def stop(self):
        self.pg(f"{PGBIN}/pg_ctl -D {self.dir}/data -w -m fast stop")

    def restart(self):
        self.stop()
        self.start(first=False)

    def sql(self, q, db="ferrosip"):
        r = run(["psql", "-h", "127.0.0.1", "-p", str(PG_PORT), "-U", "postgres", "-d", db, "-t", "-A", "-F", "|", "-c", q])
        if r.returncode:
            raise RuntimeError(r.stderr)
        return [l.split("|") for l in r.stdout.strip().splitlines() if l]

    def cleanup(self):
        self.stop()
        shutil.rmtree(self.dir, ignore_errors=True)


class MariaDb:
    name = "mysql"

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="ferrosip-my-")
        self.plain_url = f"mysql://root@127.0.0.1:{MY_PORT}/ferrosip"
        self.url = f"{self.plain_url}?ssl=1&ssl_ca={TLS}/ca.pem"
        self.proc = None

    @staticmethod
    def available():
        return shutil.which("mariadbd") is not None and shutil.which("mariadb-install-db") is not None

    def start(self, first=True):
        if first:
            r = run(["mariadb-install-db", "--no-defaults", f"--datadir={self.dir}/data", "--user=root", "--auth-root-authentication-method=normal"])
            if r.returncode:
                raise RuntimeError(r.stderr)
        self.proc = subprocess.Popen(["mariadbd", "--no-defaults", f"--datadir={self.dir}/data", f"--port={MY_PORT}", "--bind-address=127.0.0.1",
                                      f"--socket={self.dir}/sock", "--user=root", "--skip-grant-tables", "--skip-log-bin",
                                      f"--ssl-cert={TLS}/server.pem", f"--ssl-key={TLS}/server.key.pem", f"--ssl-ca={TLS}/ca.pem",
                                      "--require-secure-transport=ON", f"--log-error={self.dir}/err"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time() + 20
        while time.time() < end:
            if run(["mariadb", "--no-defaults", "-S", f"{self.dir}/sock", "-u", "root", "-e", "select 1"]).returncode == 0:
                break
            time.sleep(0.2)
        if first:
            self.sql("create database ferrosip", db="")
            r = run(f"mariadb --no-defaults -S {self.dir}/sock -u root ferrosip < {ROOT}/etc/schema/mysql.sql")
            if r.returncode:
                raise RuntimeError(r.stderr)

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait(20)

    def restart(self):
        self.stop()
        self.start(first=False)

    def sql(self, q, db="ferrosip"):
        r = run(["mariadb", "--no-defaults", "-S", f"{self.dir}/sock", "-u", "root", "-N", "-B"] + ([db] if db else []) + ["-e", q])
        if r.returncode:
            raise RuntimeError(r.stderr)
        return [l.split("\t") for l in r.stdout.strip().splitlines() if l]

    def cleanup(self):
        self.stop()
        shutil.rmtree(self.dir, ignore_errors=True)


# ------------------------------------------------------------------ SIP --
def msg(method, ruri, extra="", frm="sip:caller@x", callid=None, cseq=1, contact=True, to=None):
    seq[0] += 1
    ex = "".join(l + "\r\n" for l in extra.split("\n") if l)
    ct = f"Contact: <sip:caller@127.0.0.1:{CALLER}>\r\n" if contact else ""
    return (f"{method} {ruri} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{CALLER};branch=z9hG4bKq{seq[0]}x{time.time_ns()}\r\n"
            f"Max-Forwards: 70\r\nFrom: <{frm}>;tag=c{seq[0]}\r\nTo: <{to or ruri}>\r\nCall-ID: {callid or f'sq-{seq[0]}-{time.time_ns()}'}\r\n"
            f"CSeq: {cseq} {method}\r\n{ct}{ex}Content-Length: 0\r\n\r\n").encode()


def ctl(*args):
    out = run([f"{ROOT}/target/release/ferroctl", "-s", SOCK, *args])
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        return out.stdout + out.stderr


def proxy(url):
    cfg = os.path.join(ROOT, "target/e2e_sqldb.cfg")
    open(cfg, "w").write(CFG.replace("URL", url))
    p = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PROXY}", "-n", "2", "--rpc-socket", SOCK],
                         stderr=subprocess.PIPE, text=True)
    end = time.time() + 10
    while time.time() < end and not os.path.exists(SOCK):
        if p.poll() is not None:
            break
        time.sleep(0.05)
    time.sleep(0.2)
    return p


def stop(p):
    p.terminate()
    try:
        return p.communicate(timeout=5)[1]
    except subprocess.TimeoutExpired:
        p.kill()
        return p.communicate()[1]


def backend(db, caller, ua, ds1, ds2):
    tag = f"[{db.name}] "
    if db.name == "postgres":
        # pg_hba allows only hostssl: a plaintext URL must not connect.
        p = proxy(db.plain_url)
        err = stop(p) if p.poll() is None else p.communicate()[1]
        check(tag + "server requires TLS: plaintext db_url refused at startup", "connect" in err and "listening on" not in err, err[-300:])
    else:
        # (--skip-grant-tables makes MariaDB accept plaintext anyway: count TLS handshakes instead.)
        db.ssl_before = int(db.sql("show global status like 'Ssl_accepts'")[0][1])
    db.sql("insert into subscriber(username, domain, password, rpid) values('alice', 'x', 'secret', '+4930111')")
    db.sql(f"insert into dispatcher(setid, destination, flags, priority) values(1, 'sip:127.0.0.1:{DS1}', 0, 0)")
    p = proxy(db.url)
    err = ""
    try:
        def ask(m):
            caller.s.sendto(m, ("127.0.0.1", PROXY))
            return caller.final()

        # auth_db + usrloc
        reg = lambda auth="", cseq=1: msg("REGISTER", f"sip:127.0.0.1:{PROXY}", f"Contact: <sip:alice@127.0.0.1:{UA}>" + auth, frm="sip:alice@x",
                                          to="sip:alice@x", callid="reg-alice", cseq=cseq, contact=False)
        r = ask(reg())
        nonce = re.search(r'nonce="([^"]+)"', hdr(r or b"", "WWW-Authenticate"))
        h = lambda s: hashlib.md5(s.encode()).hexdigest()
        resp = h(f"{h('alice:x:secret')}:{nonce.group(1)}:{h(f'REGISTER:sip:127.0.0.1:{PROXY}')}") if nonce else ""
        auth = f'\nAuthorization: Digest username="alice", realm="x", nonce="{nonce.group(1) if nonce else ""}", uri="sip:127.0.0.1:{PROXY}", response="{resp}"'
        r = ask(reg(auth, 2))
        if db.name == "mysql":
            n = int(db.sql("show global status like 'Ssl_accepts'")[0][1])
            check(tag + "connections use TLS (Ssl_accepts grew)", n > db.ssl_before, (db.ssl_before, n))
        check(tag + "auth_db: credentials and rpid from the subscriber table", first(r) == "SIP/2.0 200 OK" and hdr(r, "X-RPID") == "+4930111", r)
        rows = db.sql("select username, contact, expires > 0, cseq from location")
        check(tag + "usrloc db_mode=1: contact row written", len(rows) == 1 and rows[0][0] == "alice" and rows[0][1] == f"sip:alice@127.0.0.1:{UA}"
              and rows[0][2] in ("t", "1") and rows[0][3] == "2", rows)

        # dispatcher
        caller.s.sendto(msg("MESSAGE", f"sip:ds@127.0.0.1:{PROXY}"), ("127.0.0.1", PROXY))
        m = ds1.answer("MESSAGE")
        check(tag + "dispatcher: set 1 loaded from the db", m is not None and first(caller.final()) == "SIP/2.0 200 OK", m)
        db.sql(f"insert into dispatcher(setid, destination, flags, priority) values(1, 'sip:127.0.0.1:{DS2}', 0, 0)")
        rl = ctl("dispatcher.reload")
        lst = json.dumps(ctl("dispatcher.list"))
        check(tag + "dispatcher.reload picks up a new row", f"127.0.0.1:{DS2}" in lst, (rl, lst))

        # acc
        cid = f"acc-{time.time_ns()}"
        caller.s.sendto(msg("MESSAGE", f"sip:acc@127.0.0.1:{PROXY}", callid=cid), ("127.0.0.1", PROXY))
        ua.answer("MESSAGE")
        caller.final()
        time.sleep(0.2)
        rows = db.sql(f"select method, sip_code, src_user, dst_user from acc where callid = '{cid}'")
        check(tag + "acc: transaction row with db_extra columns", rows == [["MESSAGE", "200", "caller", "acc"]], rows)

        # sqlops
        r = ask(msg("OPTIONS", f"sip:sql@127.0.0.1:{PROXY}"))
        check(tag + "sqlops: sql_query, $dbr rows/[r,c]/colname; update returns ok", hdr(r, "X-SQL") == "1 1 alice u upd=1", hdr(r, "X-SQL"))
        check(tag + "…the update reached the database", db.sql("select rpid from subscriber where username = 'alice'") == [["changed"]])
        cid = f"async-{time.time_ns()}"
        r = ask(msg("OPTIONS", f"sip:async@127.0.0.1:{PROXY}", callid=cid))
        time.sleep(0.3)
        check(tag + "sql_query_async: row inserted in the background", first(r) == "SIP/2.0 200 queued" and db.sql(f"select sip_reason from acc where callid = '{cid}'") == [["async"]])

        # database server restart: the pool reconnects
        db.restart()
        r = ask(msg("OPTIONS", f"sip:sql@127.0.0.1:{PROXY}"))
        check(tag + "database restarted: next query reconnects", hdr(r, "X-SQL").startswith("1 1 alice"), (r, hdr(r or b"", "X-SQL")))

        # proxy restart: contacts come back from the db
        err += stop(p)
        p = proxy(db.url)
        # The REGISTER came from the caller's socket: lookup() sends to that
        # received address, with the registered contact as R-URI.
        caller.s.sendto(msg("MESSAGE", f"sip:alice@127.0.0.1:{PROXY}"), ("127.0.0.1", PROXY))
        m = caller.answer("MESSAGE")
        check(tag + "proxy restarted: contact loaded from the location table, lookup works", m is not None
              and first(m) == f"MESSAGE sip:alice@127.0.0.1:{UA} SIP/2.0" and first(caller.final()) == "SIP/2.0 200 OK", m)
    finally:
        err += stop(p)
        check(tag + "no panics in proxy log", "panicked" not in err, err[-1500:])
        if failures:
            print("--- proxy stderr ---\n" + err[-3000:])


def main():
    caller, ua, ds1, ds2 = Peer(CALLER), Peer(UA), Peer(DS1), Peer(DS2)
    ran = 0
    version = subprocess.run([f"{ROOT}/target/release/ferrosip", "--version"], capture_output=True, text=True).stdout
    for cls in (Postgres, MariaDb):
        if f"db-{cls.name}" not in version.replace("(", " ").replace(")", " ").split():
            print(f"SKIP {cls.name}: ferrosip built without db-{cls.name} (cargo build --release --features ferrosip/db-all)")
            continue
        if not cls.available():
            print(f"SKIP {cls.name}: server binaries not installed")
            continue
        db = cls()
        for peer in (caller, ua, ds1, ds2):
            peer.drain()
        try:
            db.start()
            backend(db, caller, ua, ds1, ds2)
            ran += 1
        except RuntimeError as e:
            check(f"[{cls.name}] server setup", False, str(e)[-1500:])
        finally:
            db.cleanup()
    check("at least one SQL backend tested", ran > 0)
    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
