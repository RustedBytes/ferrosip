import { useMemo, useState } from "preact/hooks";
import type { Row } from "../api";
import { label, rowCount, text } from "../format";
import type { Column } from "./Table";
import { clampOffset, Pager, usePageSize } from "./Pager";
import { Drawer, Empty, KeyValues } from "./ui";

/** A table over rows already in the browser: search and sort locally. */
export function LocalTable({ rows, columns, title, emptyText }: { rows: Row[]; columns: Column[]; title?: (r: Row) => string; emptyText?: string }) {
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<{ key: string; desc: boolean } | undefined>();
  const [open, setOpen] = useState<Row | undefined>();
  const [offset, setOffset] = useState(0);
  const [size, setSize] = usePageSize();
  const shown = useMemo(() => {
    const n = q.toLowerCase();
    let out = n ? rows.filter((r) => JSON.stringify(r).toLowerCase().includes(n)) : rows.slice();
    if (sort) {
      const { key, desc } = sort;
      out = out.sort((a, b) => {
        const x = a[key];
        const y = b[key];
        const o = typeof x === "number" && typeof y === "number" ? x - y : text(x).localeCompare(text(y));
        return desc ? -o : o;
      });
    }
    return out;
  }, [rows, q, sort]);
  const start = clampOffset(offset, shown.length, size);

  return (
    <div class="table-wrap">
      <div class="table-tools">
        <input
          type="search"
          placeholder="Search…"
          aria-label="Search"
          value={q}
          onInput={(e) => {
            setQ((e.target as HTMLInputElement).value);
            setOffset(0);
          }}
        />
        <span class="muted">{rowCount(shown.length)}</span>
      </div>
      {shown.length === 0 ? (
        <Empty>{q ? "No rows match." : (emptyText ?? "Nothing to show.")}</Empty>
      ) : (
        <div class="scroll-x">
          <table>
            <thead>
              <tr>
                {columns.map((c) => {
                  const dir = sort?.key === c.key ? (sort.desc ? "descending" : "ascending") : undefined;
                  return (
                    <th key={c.key} class={c.numeric ? "num" : undefined} aria-sort={dir}>
                      <button class="th-sort" onClick={() => setSort(sort?.key === c.key ? (sort.desc ? undefined : { key: c.key, desc: true }) : { key: c.key, desc: false })}>
                        {c.label ?? label(c.key)}
                        <span class="sort-mark">{dir === "ascending" ? "▲" : dir === "descending" ? "▼" : ""}</span>
                      </button>
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody>
              {shown.slice(start, start + size).map((r, i) => (
                <tr key={i} class="clickable" tabIndex={0} onClick={() => setOpen(r)} onKeyDown={(e) => e.key === "Enter" && setOpen(r)}>
                  {columns.map((c) => (
                    <td key={c.key} class={c.numeric ? "num" : undefined}>
                      {c.render ? c.render(r) : text(r[c.key])}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Pager total={shown.length} offset={start} size={size} onOffset={setOffset} onSize={setSize} />
      {open && (
        <Drawer title={title ? title(open) : "Details"} onClose={() => setOpen(undefined)}>
          <KeyValues data={open} />
        </Drawer>
      )}
    </div>
  );
}
