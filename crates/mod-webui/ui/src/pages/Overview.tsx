import type { Row } from "../api";
import { Card, ErrorNote, Tile } from "../components/ui";
import { bytes, dateTime, duration, number } from "../format";
import { usePoll } from "../hooks";
import { useStats } from "../stats";

interface Info {
  version: string;
  pid: number;
  started: number;
  rss_kb?: number;
  threads?: number;
  config: string;
  listeners: { proto: string; addr: string; workers: string }[];
  modules: string[];
}

export function Overview() {
  const info = usePoll<Info>("info");
  const up = usePoll<{ uptime: number }>("uptime");
  const st = useStats();
  const rate = (k: string) => st.rate(k);
  const sum = (...ks: string[]) => ks.reduce((a, k) => a + (st.value(k) ?? 0), 0);
  const replyRate = (c: string) => rate(`tm:${c}`) ?? 0;
  const i = info.data;

  const tiles: { label: string; key: string; value: string; sub?: string }[] = [
    { label: "Requests / s", key: "core:rcv_requests", value: number(rate("core:rcv_requests"), 1), sub: `${number(st.value("core:rcv_requests"))} total` },
    { label: "Replies / s", key: "core:rcv_replies", value: number(rate("core:rcv_replies"), 1), sub: `${number(st.value("core:rcv_replies"))} total` },
    { label: "Transactions", key: "tm:current", value: number(st.value("tm:current")), sub: "in progress" },
    { label: "Active dialogs", key: "dialog:active_dialogs", value: number(st.value("dialog:active_dialogs")), sub: `${number(st.value("dialog:early_dialogs"))} early` },
    { label: "AI calls", key: "ai:active_calls", value: number(st.value("ai:active_calls")), sub: `${number(st.value("ai:calls"))} total` },
    { label: "Registered users", key: "usrloc:registered_users", value: number(st.value("usrloc:registered_users")), sub: `${number(st.value("usrloc:location-contacts"))} contacts` },
    { label: "TCP/TLS/WS connections", key: "tcp:active_connections", value: number(st.value("tcp:active_connections")), sub: st.current.has("tcp:accepted") ? `${number(st.value("tcp:accepted"))} accepted` : undefined },
    { label: "Retransmissions / s", key: "tm:retransmissions", value: number(rate("tm:retransmissions"), 1) },
    { label: "Timeouts / s", key: "tm:timeouts", value: number(rate("tm:timeouts"), 1), sub: `${number(st.value("tm:timeouts"))} total` },
  ].filter((t) => st.current.has(t.key) || t.key.startsWith("core:"));

  return (
    <div class="page">
      <ErrorNote error={info.error ?? st.error} />
      <div class="tiles">
        {tiles.map((t) => (
          <Tile key={t.key} label={t.label} value={t.value} sub={t.sub} history={st.history(t.key)} />
        ))}
      </div>
      {st.current.has("tm:2xx") && (
        <Card title="Final replies (per second)">
          <div class="classes">
            {["2xx", "3xx", "4xx", "5xx", "6xx"].map((c) => (
              <div key={c} class={`class c${c[0]}`}>
                <span class="class-label">{c}</span>
                <span class="class-value">{number(replyRate(c), 1)}</span>
                <span class="muted">{number(st.value(`tm:${c}`))} total</span>
              </div>
            ))}
          </div>
        </Card>
      )}
      <div class="grid2">
        <Card title="Process">
          {i && (
            <dl class="kv">
              <div><dt>Version</dt><dd>ferrosip {i.version}</dd></div>
              <div><dt>Uptime</dt><dd>{duration(up.data?.uptime)} (since {dateTime(i.started)})</dd></div>
              <div><dt>PID</dt><dd>{i.pid}</dd></div>
              <div><dt>Memory (RSS)</dt><dd>{bytes(i.rss_kb)}</dd></div>
              <div><dt>Threads</dt><dd>{number(i.threads)}</dd></div>
              <div><dt>Script</dt><dd><code>{i.config}</code></dd></div>
              <div><dt>Panics</dt><dd>{number(sum("core:panics"))}</dd></div>
            </dl>
          )}
        </Card>
        <Card title="Listeners">
          {i && (
            <table>
              <thead><tr><th>Protocol</th><th>Address</th><th>Workers</th></tr></thead>
              <tbody>
                {i.listeners.map((l) => (
                  <tr key={`${l.proto}${l.addr}`}><td><span class="badge">{l.proto}</span></td><td><code>{l.addr}</code></td><td>{l.workers}</td></tr>
                ))}
              </tbody>
            </table>
          )}
          <h3>Modules</h3>
          <p class="chips">{i?.modules.map((m) => <span key={m} class="chip">{m}</span>)}</p>
        </Card>
      </div>
    </div>
  );
}

export type { Row };
