import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
import "./styles.css";
import { get, type Meta } from "./api";
import { ErrorNote } from "./components/ui";
import { time } from "./format";
import { LiveContext, navigate, useRoute } from "./hooks";
import { Calls } from "./pages/Calls";
import { Connections } from "./pages/Connections";
import { Logs } from "./pages/Logs";
import { Overview } from "./pages/Overview";
import { Registrations } from "./pages/Registrations";
import { Section } from "./pages/Section";
import { Statistics } from "./pages/Statistics";
import { StatsProvider, useStats } from "./stats";

/** Navigation order; a section is listed when /api/v1/meta has it. */
const NAV: { id: string; title: string }[] = [
  { id: "overview", title: "Overview" },
  { id: "statistics", title: "Statistics" },
  { id: "registrations", title: "Registrations" },
  { id: "calls", title: "Calls" },
  { id: "transactions", title: "Transactions" },
  { id: "connections", title: "Connections" },
  { id: "routing", title: "Routing" },
  { id: "health", title: "Health" },
  { id: "security", title: "Security" },
  { id: "data", title: "Data" },
  { id: "presence", title: "Presence" },
  { id: "logs", title: "Logs" },
];

function Page({ id, meta, tab }: { id: string; meta: Meta; tab?: string }) {
  const paths = meta.sections[id] ?? [];
  switch (id) {
    case "overview":
      return <Overview />;
    case "statistics":
      return <Statistics />;
    case "registrations":
      return <Registrations paths={paths} />;
    case "calls":
      return <Calls paths={paths} />;
    case "connections":
      return <Connections />;
    case "logs":
      return <Logs />;
    default:
      return <Section paths={paths} tab={tab} onTab={(t) => navigate(id, { tab: t })} />;
  }
}

function Updated() {
  const st = useStats();
  return <span class="muted updated">{st.updated ? `Updated ${time(st.updated)}` : ""}</span>;
}

function App() {
  const [meta, setMeta] = useState<Meta>();
  const [error, setError] = useState<string>();
  const [paused, setPaused] = useState(false);
  const [page, qs] = useRoute();
  const [menu, setMenu] = useState(false);

  // The burger menu (narrow screens) closes on navigation and on Escape.
  useEffect(() => setMenu(false), [page]);
  useEffect(() => {
    if (!menu) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setMenu(false);
    addEventListener("keydown", onKey);
    return () => removeEventListener("keydown", onKey);
  }, [menu]);

  useEffect(() => {
    get<Meta>("meta").then(setMeta, (e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  const nav = NAV.filter((n) => n.id === "overview" || meta?.sections[n.id]);
  const current = nav.find((n) => n.id === page) ?? nav[0];
  useEffect(() => {
    document.title = `${current?.title ?? "ferrosip"} · ferrosip`;
  }, [current?.id]);

  if (error) return <ErrorNote error={`Cannot reach the API: ${error}`} />;
  if (!meta) return <p class="empty">Loading…</p>;
  return (
    <LiveContext.Provider value={{ paused, intervalMs: meta.refresh_ms }}>
      <StatsProvider>
        <div class={menu ? "shell menu-open" : "shell"}>
          <aside class="sidebar" id="sidebar">
            <div class="brand">
              <img src="/favicon.svg" alt="" width="24" height="24" />
              <span>ferrosip</span>
              <span class="muted version">{meta.version}</span>
            </div>
            <nav aria-label="Sections">
              {nav.map((n) => (
                <a key={n.id} href={`#/${n.id}`} onClick={() => setMenu(false)} class={n.id === current?.id ? "nav-link active" : "nav-link"} aria-current={n.id === current?.id ? "page" : undefined}>
                  {n.title}
                </a>
              ))}
            </nav>
            <p class="readonly muted">Read-only view</p>
          </aside>
          {menu && <div class="backdrop" onClick={() => setMenu(false)} />}
          <main>
            <header class="topbar">
              <button class="burger" aria-label="Menu" aria-expanded={menu} aria-controls="sidebar" onClick={() => setMenu(!menu)}>
                <span aria-hidden="true">☰</span>
              </button>
              <h1>{current?.title}</h1>
              <div class="topbar-right">
                <Updated />
                <button class={paused ? "live paused" : "live"} onClick={() => setPaused(!paused)} aria-pressed={paused}>
                  {paused ? "▶ Resume" : "❚❚ Pause"}
                </button>
              </div>
            </header>
            {current && <Page id={current.id} meta={meta} tab={qs.get("tab") ?? undefined} />}
          </main>
        </div>
      </StatsProvider>
    </LiveContext.Provider>
  );
}

render(<App />, document.getElementById("app")!);
