// Bundle src/ with esbuild and write the embedded assets to ../assets:
// index.html, app.js.gz, app.css.gz (gzip without a timestamp, so the same
// sources always give the same bytes and CI can check they're committed).
import { build } from "esbuild";
import { gzipSync } from "node:zlib";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

const out = new URL("../assets/", import.meta.url);
mkdirSync(new URL("dist/", import.meta.url), { recursive: true });

await build({
  entryPoints: ["src/main.tsx"],
  bundle: true,
  minify: true,
  format: "esm",
  target: ["es2020"],
  jsx: "automatic",
  jsxImportSource: "preact",
  outdir: "dist",
  entryNames: "app",
  legalComments: "none",
  logLevel: "warning",
});

for (const name of ["app.js", "app.css"]) {
  const src = readFileSync(new URL(`dist/${name}`, import.meta.url));
  const gz = gzipSync(src, { level: 9 });
  gz[9] = 3; // OS = Unix whatever the build machine: identical bytes everywhere
  writeFileSync(new URL(`${name}.gz`, out), gz);
  console.log(`${name}: ${src.length} bytes, ${gz.length} gzipped`);
}
copyFileSync(new URL("index.html", import.meta.url), new URL("index.html", out));
copyFileSync(new URL("favicon.svg", import.meta.url), new URL("favicon.svg", out));
