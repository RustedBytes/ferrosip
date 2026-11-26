import { useState } from "preact/hooks";
import type { ComponentChildren } from "preact";
import type { Row } from "../api";
import { Table } from "../components/Table";
import { Badge, Card, Drawer, KeyValues, Tabs, Tile } from "../components/ui";
import { dateTime, duration, label, number, text } from "../format";
import { usePoll } from "../hooks";
import { useStats } from "../stats";

const TABS: Record<string, string> = { dialogs: "Dialogs", "ai-calls": "AI calls", dlgs: "dlgs", cnxcc: "Credit control" };

/** Dialog states in call order; the total last. */
const ORDER = ["starting", "connecting", "answering", "ongoing", "all"];

function DialogTotals() {
  const s = usePoll<Row>("dialogs/stats");
  if (!s.data) return null;
  return (
    <div class="tiles">
      {Object.entries(s.data)
        .sort(([a], [b]) => ORDER.indexOf(a) - ORDER.indexOf(b))
        .map(([k, v]) => (
          <Tile key={k} label={k === "all" ? "All dialogs" : label(k)} value={number(v as number)} />
        ))}
    </div>
  );
}

/** The first line of a prompt, cut short; the drawer has all of it. */
function Prompt({ value }: { value: unknown }): ComponentChildren {
  const t = text(value);
  return (
    <span class="prompt-preview" title={t}>
      {t.split("\n")[0]}
    </span>
  );
}

function AiTotals() {
  const st = useStats();
  const tiles = [
    { key: "ai:active_calls", label: "AI calls now" },
    { key: "ai:calls", label: "AI calls total" },
    { key: "ai:failed_calls", label: "Failed to connect" },
  ].filter((t) => st.current.has(t.key));
  if (tiles.length === 0) return null;
  return (
    <div class="tiles">
      {tiles.map((t) => (
        <Tile key={t.key} label={t.label} value={number(st.value(t.key))} history={st.history(t.key)} />
      ))}
    </div>
  );
}

/** A call's details, with its timestamps as dates. */
function AiDetail({ row }: { row: Row }) {
  const shown: Row = { ...row, started: dateTime(row.started as number) };
  if (row.ended) shown.ended = dateTime(row.ended as number);
  return <KeyValues data={shown} />;
}

function AiCalls() {
  const title = (r: Row) => `${text(r.provider)} call ${text(r.call_id)}`;
  const detail = (r: Row) => <AiDetail row={r} />;
  return (
    <>
      <AiTotals />
      <Card title="In progress">
        <Table
          path="ai-calls"
          columns={[
            { key: "state", render: (r) => <Badge value={r.state} /> },
            { key: "provider" },
            { key: "duration", numeric: true, render: (r) => duration(r.duration as number) },
            { key: "from" },
            { key: "prompt", render: (r) => <Prompt value={r.prompt} /> },
            { key: "codec" },
            { key: "rtp_in", label: "RTP in", numeric: true },
            { key: "rtp_out", label: "RTP out", numeric: true },
          ]}
          title={title}
          detail={detail}
          emptyText="No AI calls right now."
        />
      </Card>
      <Card title="Recently ended">
        <Table
          path="ai-calls/recent"
          columns={[
            { key: "ended", render: (r) => dateTime(r.ended as number) },
            { key: "outcome", render: (r) => <Badge value={r.outcome} /> },
            { key: "provider" },
            { key: "duration", numeric: true, render: (r) => duration(r.duration as number) },
            { key: "from" },
            { key: "reason" },
            { key: "prompt", render: (r) => <Prompt value={r.prompt} /> },
          ]}
          title={title}
          detail={detail}
          emptyText="No AI call has ended yet."
        />
      </Card>
    </>
  );
}

function Client({ id }: { id: string }) {
  const c = usePoll<Row>("cnxcc/client", { client: id });
  return <KeyValues data={c.data} />;
}

export function Calls({ paths }: { paths: string[] }) {
  const tabs = Object.keys(TABS).filter((p) => paths.includes(p)).map((id) => ({ id, label: TABS[id] }));
  const [tab, setTab] = useState(tabs[0]?.id ?? "dialogs");
  const [client, setClient] = useState<string | undefined>();

  return (
    <div class="page">
      {tabs.length > 1 && <Tabs tabs={tabs} active={tab} onChange={setTab} />}
      {tab === "dialogs" && (
        <>
          <DialogTotals />
          <Card>
            <Table
              path="dialogs"
              columns={[
                { key: "state_name", label: "State", render: (r) => <Badge value={r.state_name} /> },
                { key: "duration", numeric: true, render: (r) => duration(r.duration as number) },
                { key: "from_uri", label: "From" },
                { key: "to_uri", label: "To" },
                { key: "call-id", label: "Call ID" },
                { key: "caller_contact", label: "Caller contact" },
              ]}
              title={(r) => text(r["call-id"])}
              emptyText="No active dialogs."
            />
          </Card>
        </>
      )}
      {tab === "ai-calls" && <AiCalls />}
      {tab === "dlgs" && (
        <Card>
          <Table path="dlgs" title={(r) => text(r.callid)} />
        </Card>
      )}
      {tab === "cnxcc" && (
        <Card>
          <Table path="cnxcc" onRow={(r) => setClient(String(r.client_id))} />
        </Card>
      )}
      {client && (
        <Drawer title={`Client ${client}`} onClose={() => setClient(undefined)}>
          <Client id={client} />
        </Drawer>
      )}
    </div>
  );
}
