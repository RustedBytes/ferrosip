// Render the ferrosip dashboard to a PNG (Playwright + Chromium).
//
//   node screenshot.mjs [out.png] [grafana-url]
//
// Uses Grafana's anonymous viewer and kiosk mode; the viewport is tall
// enough that every panel loads (Grafana renders panels lazily).
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
let playwright;
try {
  playwright = require("playwright");
} catch {
  playwright = require(require("node:child_process").execSync("npm root -g").toString().trim() + "/playwright");
}

const out = process.argv[2] ?? "dashboard.png";
const grafana = process.argv[3] ?? "http://127.0.0.1:3000";
const browser = await playwright.chromium.launch();
const page = await browser.newPage({ viewport: { width: 1600, height: 3600 }, deviceScaleFactor: 2, colorScheme: "dark" });
await page.goto(`${grafana}/d/ferrosip/ferrosip?orgId=1&kiosk&from=now-15m&to=now&refresh=`, { waitUntil: "networkidle" });
await page.waitForSelector("[data-testid='data-testid panel content'], .panel-content", { timeout: 30000 }).catch(() => {});
await page.waitForTimeout(6000); // let every panel finish its query and draw
// Crop to the last panel (the viewport is taller than the dashboard).
const bottom = await page.evaluate(() => Math.max(0, ...[...document.querySelectorAll(".react-grid-item")].map((e) => e.getBoundingClientRect().bottom + window.scrollY)));
await page.screenshot(bottom > 0 ? { path: out, clip: { x: 0, y: 0, width: 1600, height: Math.ceil(bottom) + 16 } } : { path: out, fullPage: true });
await browser.close();
console.log(`wrote ${out}`);
