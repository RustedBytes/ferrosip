import { useEffect, useState } from "preact/hooks";
import type { Row } from "../api";
import { type Column, Table } from "../components/Table";
import { Badge, Card, Drawer, Empty, Tabs } from "../components/ui";
import { dateTime, duration, text } from "../format";

/** Tab names for API paths. */
const LABELS: Record<string, string> = {
  tm: "Transactions",
  blocklist: "Destination blocklist",
  tsilo: "tsilo",
  dispatcher: "Dispatcher",
  "lcr/gateways": "LCR gateways",
  "lcr/rules": "LCR rules",
  dialplan: "Dialplan",
  mtree: "mtree",
  "prefix-route": "Prefix routes",
  keepalive: "Keepalive",
  rtpengine: "RTPengine",
  "cdp-peers": "Diameter peers",
  "ims/pcscf": "P-CSCF contacts",
  "ims/scscf": "S-CSCF users",
  "ims/ro": "Ro sessions",
  "ims/ipsec": "IPsec",
  pike: "Pike",
  ratelimit: "Ratelimit",
  pipelimit: "Pipelimit",
  secfilter: "Secfilter",
  "secfilter/stats": "Secfilter stats",
  userblocklist: "User blocklist",
  "permissions/address": "Address table",
  "permissions/trusted": "Trusted table",
  domains: "Domains",
  htable: "Hash tables",
  cfg: "Config variables",
  siptrace: "siptrace",
  sipdump: "sipdump",
  "presence/presentities": "Presentities",
  "presence/watchers": "Watchers",
  "sca/subscriptions": "SCA subscriptions",
  "sca/appearances": "SCA appearances",
};

/** Views whose columns are chosen rather than derived from the data. */
const COLUMNS: Record<string, Column[]> = {
  dispatcher: [
    { key: "set", numeric: true },
    { key: "uri", label: "Destination" },
    { key: "state", render: (r) => <Badge value={r.state} /> },
    { key: "probing", render: (r) => <Badge value={r.probing ? "probing" : "—"} /> },
    { key: "priority", numeric: true },
    { key: "load", numeric: true },
    { key: "latency_avg", label: "Latency avg (ms)", numeric: true },
    { key: "timeouts", numeric: true },
    { key: "attrs" },
  ],
  keepalive: [
    { key: "uri", label: "Destination" },
    { key: "state", render: (r) => <Badge value={r.state} /> },
    { key: "failures", numeric: true },
    { key: "last_up", label: "Last up", render: (r) => dateTime(r.last_up as number) },
    { key: "last_down", label: "Last down", render: (r) => dateTime(r.last_down as number) },
    { key: "owner" },
  ],
  pike: [
    { key: "ip", label: "Address" },
    { key: "blocked", render: (r) => <Badge value={r.blocked ? "blocked" : "ok"} /> },
    { key: "hits", numeric: true },
    { key: "prev", label: "Previous", numeric: true },
  ],
  blocklist: [
    { key: "proto" },
    { key: "addr", label: "Address" },
    { key: "expires_in", label: "Expires in", numeric: true, render: (r) => duration(r.expires_in as number) },
  ],
};

/** Paths only reached from a row of another view. */
const DETAIL_ONLY = new Set(["htable/items", "registrations/contacts", "cnxcc/client", "logs"]);

function HashTables() {
  const [table, setTable] = useState<string | undefined>();
  return (
    <>
      <Table path="htable" onRow={(r: Row) => setTable(String(r.name))} emptyText="No hash tables." />
      {table && (
        <Drawer title={`Hash table ${table}`} onClose={() => setTable(undefined)}>
          <Table path="htable/items" params={{ table }} title={(r) => text(r.name)} emptyText="The table is empty." />
        </Drawer>
      )}
    </>
  );
}

function Dialplan() {
  const [dpid, setDpid] = useState("0");
  return (
    <>
      <div class="table-tools">
        <label>
          Dialplan id{" "}
          <input type="number" min="0" value={dpid} aria-label="Dialplan id" onInput={(e) => setDpid((e.target as HTMLInputElement).value)} />
        </label>
      </div>
      <Table path="dialplan" params={{ dpid }} emptyText="No rules for this id." />
    </>
  );
}

function View({ path }: { path: string }) {
  if (path === "htable") return <HashTables />;
  if (path === "dialplan") return <Dialplan />;
  return <Table path={path} columns={COLUMNS[path]} />;
}

/** A section: one tab per API path its loaded modules provide. */
export function Section({ paths, tab, onTab }: { paths: string[]; tab?: string; onTab: (t: string) => void }) {
  const views = paths.filter((p) => !DETAIL_ONLY.has(p));
  const active = tab && views.includes(tab) ? tab : views[0];
  useEffect(() => {
    if (tab && !views.includes(tab) && views[0]) onTab(views[0]);
  }, [tab, views.join()]);
  if (!active) return <Empty>Nothing here: none of this section's modules is loaded.</Empty>;
  return (
    <div class="page">
      {views.length > 1 && <Tabs tabs={views.map((p) => ({ id: p, label: LABELS[p] ?? p }))} active={active} onChange={onTab} />}
      <Card title={LABELS[active] ?? active}>
        <View key={active} path={active} />
      </Card>
    </div>
  );
}
