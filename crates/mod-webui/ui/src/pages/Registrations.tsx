import { useState } from "preact/hooks";
import type { Row } from "../api";
import { Table } from "../components/Table";
import { Card, Drawer, Tabs } from "../components/ui";
import { duration, text } from "../format";

function Contacts({ aor }: { aor: string }) {
  return (
    <Table
      path="registrations/contacts"
      params={{ aor }}
      columns={[
        { key: "contact" },
        { key: "expires", label: "Expires in", numeric: true, render: (r) => duration(r.expires as number) },
        { key: "received", label: "Received from" },
        { key: "user_agent" },
        { key: "q", numeric: true },
      ]}
      title={(r) => text(r.contact)}
    />
  );
}

export function Registrations({ paths }: { paths: string[] }) {
  const [aor, setAor] = useState<string | undefined>();
  const tabs = [{ id: "registrations", label: "Registered users" }];
  if (paths.includes("uac-registrations")) tabs.push({ id: "uac-registrations", label: "Outbound (uac)" });
  const [tab, setTab] = useState(tabs[0].id);

  return (
    <div class="page">
      {tabs.length > 1 && <Tabs tabs={tabs} active={tab} onChange={setTab} />}
      <Card>
        {tab === "registrations" ? (
          <Table
            path="registrations"
            columns={[
              { key: "aor", label: "AoR" },
              { key: "contacts", numeric: true },
              { key: "contact", label: "First contact" },
              { key: "received", label: "Received from" },
              { key: "user_agent" },
              { key: "expires", label: "Expires in", numeric: true, render: (r: Row) => duration(r.expires as number) },
            ]}
            onRow={(r) => setAor(String(r.aor))}
            emptyText="No registered users."
          />
        ) : (
          <Table path="uac-registrations" />
        )}
      </Card>
      {aor && (
        <Drawer title={`Contacts of ${aor}`} onClose={() => setAor(undefined)}>
          <Contacts aor={aor} />
        </Drawer>
      )}
    </div>
  );
}
