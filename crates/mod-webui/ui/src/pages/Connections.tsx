import type { Row } from "../api";
import { LocalTable } from "../components/LocalTable";
import { Badge, Card, ErrorNote, Tile } from "../components/ui";
import { duration, number, text } from "../format";
import { usePoll } from "../hooks";

interface Conns {
  active: number;
  max_connections: number;
  accept_iplimit: number;
  lifetime_s: number;
  connections: Row[];
}

export function Connections() {
  const c = usePoll<Conns>("connections");
  const d = c.data;
  return (
    <div class="page">
      <ErrorNote error={c.error} />
      {d && (
        <div class="tiles">
          <Tile label="Open connections" value={number(d.active)} sub={`limit ${number(d.max_connections)}`} />
          <Tile label="Per-IP limit" value={d.accept_iplimit ? number(d.accept_iplimit) : "none"} />
          <Tile label="Idle lifetime" value={duration(d.lifetime_s)} />
        </div>
      )}
      <Card title="TCP, TLS and WebSocket connections">
        <LocalTable
          rows={d?.connections ?? []}
          columns={[
            { key: "proto", render: (r) => <span class="badge">{text(r.proto)}</span> },
            { key: "peer" },
            { key: "local" },
            { key: "direction", render: (r) => <Badge value={r.direction} /> },
            { key: "established", render: (r) => <Badge value={r.established} /> },
            { key: "age_s", label: "Age", numeric: true, render: (r) => duration(r.age_s as number) },
            { key: "idle_s", label: "Idle", numeric: true, render: (r) => duration(r.idle_s as number) },
            { key: "tls_version", label: "TLS" },
            { key: "sni", label: "SNI" },
          ]}
          title={(r) => `Connection ${text(r.id)}`}
          emptyText="No stream connections (UDP only, or idle)."
        />
      </Card>
    </div>
  );
}
