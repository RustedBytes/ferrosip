#!/usr/bin/env node
// Browser smoke test of the web UI (Playwright + Chromium).
//
// Starts ferrosip with the webui and a few modules, gives it data (three
// registrations, an answered call, a dispatcher set, an htable entry), then
// in a real browser, logged in with Basic auth:
// - opens every page and checks what it shows;
// - drills into a registration and a hash table;
// - sees the request counter move;
// - fails on any console error or failed request.
// Screenshots go to SHOTS (default target/webui-shots).
//
//   cargo build --release && node tests/webui_browser.mjs
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import dgram from "node:dgram";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

// require() also finds a globally installed Playwright (NODE_PATH), which
// an ES import doesn't.
const { chromium } = createRequire(import.meta.url)("playwright");

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SHOTS = process.env.SHOTS ?? join(ROOT, "target/webui-shots");
// AI_DOWN: nothing listens there, so the AI call fails (503) and shows as ended.
const PROXY = 7900, UAS = 7901, UAC = 7902, WEB = 7980, AI_DOWN = 7999;
let failures = 0;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `  -- ${detail}`}`);
  if (!ok) failures++;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// True once the element is visible (data arrives by polling, so wait for
// it instead of checking at once; slow CI runners need the margin).
const seen = (locator, timeout = 5000) => locator.waitFor({ state: "visible", timeout }).then(() => true, () => false);

const hash = `sha256:salt:${createHash("sha256").update("saltpw").digest("hex")}`;
const cfg = `loadmodule "sl"
loadmodule "textops"
loadmodule "tm"
loadmodule "usrloc"
loadmodule "registrar"
loadmodule "dialog"
loadmodule "dispatcher"
loadmodule "htable"
loadmodule "webui"
loadmodule "ai"
modparam("ai", "openai_url", "ws://127.0.0.1:${AI_DOWN}/v1/realtime")
modparam("ai", "openai_key", "sk-dummy")
modparam("ai", "media_ip", "127.0.0.1")
modparam("ai", "rtp_port_min", 7940)
modparam("ai", "rtp_port_max", 7959)
modparam("dispatcher", "list_file", "${ROOT}/target/webui_browser.list")
modparam("htable", "htable", "t=>size=4;autoexpire=0;")
modparam("webui", "listen", "127.0.0.1:${WEB}")
modparam("webui", "user", "admin")
modparam("webui", "password_hash", "${hash}")
modparam("webui", "refresh_ms", 1000)
request_route {
    if (ai_dialog()) exit;
    if (is_method("INVITE") && $rU == "ai") { ai_answer("openai", "$hdr(X-AI-Prompt)"); exit; }
    if (is_method("REGISTER")) { save("location"); exit; }
    if (is_method("MESSAGE")) { $sht(t=>greeting) = "hello"; sl_send_reply(200, "OK"); exit; }
    if (is_method("OPTIONS")) { sl_send_reply(200, "OK"); exit; }
    if (is_method("INVITE")) { dlg_manage(); }
    t_relay("udp:127.0.0.1:${UAS}");
}
`;
writeFileSync(join(ROOT, "target/webui_browser.cfg"), cfg);
writeFileSync(join(ROOT, "target/webui_browser.list"), "1 sip:gw1.example.invalid:5060\n1 sip:gw2.example.invalid:5060\n");

const proxy = spawn(join(ROOT, "target/release/ferrosip"), ["-f", join(ROOT, "target/webui_browser.cfg"), "-l", `udp:127.0.0.1:${PROXY}`, "--rpc-socket", "none"], { stdio: ["ignore", "ignore", "pipe"] });
let stderr = "";
proxy.stderr.on("data", (d) => (stderr += d));

// A UAS that answers everything with 200.
const uas = dgram.createSocket("udp4");
uas.on("message", (m, r) => {
  const s = m.toString();
  if (s.startsWith("ACK") || s.startsWith("SIP/")) return;
  const keep = s.split("\r\n").slice(1).filter((h) => /^(via|from|to|call-id|cseq):/i.test(h)).map((h) => (/^to:/i.test(h) ? `${h};tag=uas` : h));
  uas.send(`SIP/2.0 200 OK\r\n${keep.join("\r\n")}\r\nContact: <sip:uas@127.0.0.1:${UAS}>\r\nContent-Length: 0\r\n\r\n`, r.port, r.address);
});
uas.bind(UAS);
const uac = dgram.createSocket("udp4");
uac.bind(UAC);
const sip = (method, user, cid, extra = "", body = "") =>
  new Promise((resolve) => {
    const on = (m) => {
      const s = m.toString();
      if (s.startsWith("SIP/2.0 1")) return;
      uac.off("message", on);
      resolve(s);
    };
    uac.on("message", on);
    uac.send(
      `${method} sip:${user}@127.0.0.1:${PROXY} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:${UAC};branch=z9hG4bK${cid}${method};rport\r\n` +
        `From: <sip:${user}@127.0.0.1>;tag=f${cid}\r\nTo: <sip:${user}@127.0.0.1>\r\nCall-ID: ${cid}\r\nCSeq: 1 ${method}\r\n` +
        `Contact: <sip:${user}@127.0.0.1:${UAC}>\r\nMax-Forwards: 70\r\n${extra}Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
      PROXY,
      "127.0.0.1",
    );
  });

let browser;
try {
  for (let i = 0; i < 50 && !stderr.includes("webui: listening"); i++) await sleep(100);
  for (const u of ["alice", "bob", "carol"]) await sip("REGISTER", u, `reg-${u}`, "Expires: 600\r\nUser-Agent: Smoke Phone 2.1\r\n");
  await sip("MESSAGE", "x", "msg-1");
  await sip("INVITE", "dave", "call-1");
  // A call to the AI whose provider is down: 503, then it is listed as ended.
  const prompt = "You are the front desk of Hotel Lumen.\nBe brief and friendly.";
  const sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 7990 RTP/AVP 0\r\n";
  const aiReply = await sip("INVITE", "ai", "ai-call-1", `X-AI-Prompt: b64:${Buffer.from(prompt).toString("base64")}\r\nContent-Type: application/sdp\r\n`, sdp);
  check("ai: the call to a down provider gets 503", aiReply.startsWith("SIP/2.0 503"), aiReply.split("\r\n")[0]);
  const toTag = (aiReply.match(/^To:.*?;tag=([^;\r\n]+)/im) ?? [])[1] ?? "";
  uac.send(
    `ACK sip:ai@127.0.0.1:${PROXY} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:${UAC};branch=z9hG4bKai-call-1INVITE;rport\r\nFrom: <sip:ai@127.0.0.1>;tag=fai-call-1\r\n` +
      `To: <sip:ai@127.0.0.1>;tag=${toTag}\r\nCall-ID: ai-call-1\r\nCSeq: 1 ACK\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n`,
    PROXY,
    "127.0.0.1",
  );

  mkdirSync(SHOTS, { recursive: true });
  browser = await chromium.launch();
  const ctx = await browser.newContext({ httpCredentials: { username: "admin", password: "pw" }, viewport: { width: 1360, height: 860 }, deviceScaleFactor: 2 });
  const page = await ctx.newPage();
  const problems = [];
  page.on("console", (m) => m.type() === "error" && problems.push(`console: ${m.text()}`));
  page.on("pageerror", (e) => problems.push(`page error: ${e.message}`));
  page.on("requestfailed", (r) => problems.push(`request failed: ${r.url()}`));
  page.on("response", (r) => r.status() >= 400 && problems.push(`HTTP ${r.status()}: ${r.url()}`));
  const shot = (name) => page.screenshot({ path: join(SHOTS, `${name}.png`), fullPage: true });
  const visit = async (id) => {
    await page.goto(`http://127.0.0.1:${WEB}/#/${id}`);
    await page.waitForLoadState("networkidle");
  };

  // Overview: tiles move as requests arrive.
  await visit("overview");
  await page.getByText("Requests / s").waitFor();
  check("overview: process card", await seen(page.getByText("Memory (RSS)")));
  check("overview: modules listed", await seen(page.locator(".chip", { hasText: "webui" })));
  const before = await page.locator(".tile", { hasText: "Requests / s" }).locator(".tile-sub").textContent();
  for (let i = 0; i < 20; i++) await sip("OPTIONS", "ping", `opt-${i}`);
  await sleep(2500);
  const after = await page.locator(".tile", { hasText: "Requests / s" }).locator(".tile-sub").textContent();
  check("overview: request counter moves", before !== after, `${before} → ${after}`);
  check("overview: AI calls tile", await seen(page.locator(".tile", { hasText: "AI calls" })));
  check("overview: registered users tile shows 3", (await page.locator(".tile", { hasText: "Registered users" }).locator(".tile-value").textContent()) === "3");
  await shot("overview");

  await visit("statistics");
  await page.locator("td code", { hasText: "rcv_requests" }).waitFor();
  check("statistics: counters listed with rates", await seen(page.locator("tbody tr", { hasText: "rcv_requests" }).locator(".spark")));
  await shot("statistics");

  await visit("registrations");
  await page.getByRole("cell", { name: "alice", exact: true }).waitFor();
  check("registrations: three users", (await page.locator("tbody tr").count()) === 3);
  check("registrations: user agent shown", await seen(page.getByRole("cell", { name: "Smoke Phone 2.1" }).first()));
  await page.getByRole("cell", { name: "alice", exact: true }).click();
  await page.getByRole("dialog", { name: "Contacts of alice" }).waitFor();
  check("registrations: drill-down to contacts", await seen(page.getByRole("dialog").getByText(`sip:alice@127.0.0.1:${UAC}`)));
  await shot("registrations-contacts");
  await page.keyboard.press("Escape");

  await visit("calls");
  await page.getByRole("cell", { name: "call-1" }).waitFor();
  check("calls: the dialog, with its state", await seen(page.locator("tbody tr", { hasText: "call-1" }).locator(".badge")));
  await shot("calls");
  await page.getByRole("tab", { name: "AI calls" }).click();
  const ended = page.locator("section.card", { hasText: "Recently ended" }).locator("tbody tr", { hasText: "provider unavailable" });
  await ended.waitFor();
  check("calls/AI: the failed call listed with its outcome", (await ended.locator(".badge").textContent()) === "failed");
  check("calls/AI: prompt preview shows its first line", (await ended.locator(".prompt-preview").textContent()) === "You are the front desk of Hotel Lumen.");
  check("calls/AI: nothing in progress", await seen(page.getByText("No AI calls right now.")));
  await shot("calls-ai");
  await ended.click();
  const drawer = page.getByRole("dialog");
  await drawer.waitFor();
  check("calls/AI: the drawer has the whole prompt", (await drawer.getByText("Be brief and friendly.").count()) === 1);
  check("calls/AI: drawer times shown as dates", !(await drawer.locator("dd", { hasText: /^\d{1,3}(,\d{3}){3}$/ }).count()));
  await shot("calls-ai-drawer");
  await page.keyboard.press("Escape");

  await visit("connections");
  await page.getByText("Open connections").waitFor();
  await shot("connections");

  await visit("routing");
  await page.getByRole("cell", { name: "sip:gw1.example.invalid:5060" }).waitFor();
  check("routing: dispatcher destinations", (await page.locator("tbody tr").count()) === 2);
  await shot("routing");

  await visit("data");
  await page.getByRole("cell", { name: "t", exact: true }).click();
  await page.getByRole("dialog").getByRole("cell", { name: "greeting" }).waitFor();
  check("data: hash table items", await seen(page.getByRole("dialog").getByRole("cell", { name: "hello" })));
  await shot("data-htable");
  await page.keyboard.press("Escape");

  await visit("logs");
  await page.locator(".log-line", { hasText: "webui: listening" }).waitFor();
  check("logs: startup lines", true);
  await shot("logs");

  // Pagination: 30 more users make 33 rows, two pages of 25.
  for (let i = 1; i <= 30; i++) await sip("REGISTER", `user${String(i).padStart(2, "0")}`, `reg-u${i}`, "Expires: 600\r\n");
  await visit("registrations");
  const pager = page.getByRole("navigation", { name: "Pages" });
  await pager.getByRole("button", { name: "Page 2" }).waitFor();
  check("pagination: first page holds 25", (await page.locator("tbody tr").count()) === 25);
  check("pagination: range shown", (await pager.locator(".pager-range").textContent()) === "1–25 of 33");
  await pager.getByRole("button", { name: "Next page" }).click();
  await page.waitForFunction(() => document.querySelectorAll("tbody tr").length === 8);
  check("pagination: next page holds the other 8", (await pager.locator(".pager-range").textContent()) === "26–33 of 33");
  check("pagination: page 2 is current", (await pager.getByRole("button", { name: "Page 2" }).getAttribute("aria-current")) === "page");
  await shot("registrations-page2");
  await pager.getByRole("combobox", { name: "Rows per page" }).selectOption("50");
  await page.waitForFunction(() => document.querySelectorAll("tbody tr").length === 33);
  check("pagination: 50 per page shows all", (await pager.getByRole("button", { name: "Page 2" }).count()) === 0);
  await pager.getByRole("combobox", { name: "Rows per page" }).selectOption("25");
  check("desktop: no burger button", !(await page.getByRole("button", { name: "Menu" }).isVisible()));

  // Dark mode and a phone-sized screen still render.
  await page.emulateMedia({ colorScheme: "dark" });
  await visit("overview");
  await page.getByText("Requests / s").waitFor();
  await shot("overview-dark");
  await page.setViewportSize({ width: 390, height: 844 });
  await visit("registrations");
  await page.getByRole("cell", { name: "alice", exact: true }).waitFor();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
  check("narrow screen: no horizontal page scroll", !overflow);
  await shot("registrations-phone");

  // The burger menu: navigation hidden until opened, closes on choosing.
  const sidebar = page.locator("#sidebar");
  const burger = page.getByRole("button", { name: "Menu" });
  // (It slides away when the window narrows; wait out the transition.)
  check("burger: navigation hidden on a phone", await sidebar.waitFor({ state: "hidden", timeout: 3000 }).then(() => true, () => false));
  await burger.click();
  await page.getByRole("link", { name: "Calls" }).waitFor({ state: "visible" });
  check("burger: opens the navigation", (await burger.getAttribute("aria-expanded")) === "true");
  await sleep(250);
  await page.screenshot({ path: join(SHOTS, "menu-phone.png") }); // the viewport: the menu covers it
  await page.keyboard.press("Escape");
  await sidebar.waitFor({ state: "hidden" });
  check("burger: Escape closes it", (await burger.getAttribute("aria-expanded")) === "false");
  await burger.click();
  await page.getByRole("link", { name: "Calls" }).click();
  await page.getByRole("cell", { name: "call-1" }).waitFor();
  await sidebar.waitFor({ state: "hidden" });
  check("burger: a link navigates and closes it", page.url().endsWith("#/calls"));

  check("no console errors, failed requests or HTTP errors", problems.length === 0, problems.join("; "));
} catch (e) {
  check("browser run", false, e.stack ?? String(e));
} finally {
  await browser?.close();
  proxy.kill("SIGTERM");
  uas.close();
  uac.close();
  await sleep(300);
  check("proxy: no panics", !stderr.includes("panicked"), stderr.slice(-400));
}
console.log(`\n${failures ? `${failures} FAILED` : "all passed"}  (screenshots in ${SHOTS})`);
process.exit(failures ? 1 : 0);
