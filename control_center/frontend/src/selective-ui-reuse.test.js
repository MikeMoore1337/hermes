import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";

const main = readFileSync(new URL("./main.jsx", import.meta.url), "utf8");
const styles = readFileSync(new URL("./style.css", import.meta.url), "utf8");
const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

test("native accessible primitives remain in approved Control Center", () => {
  assert.match(main, /<nav[^>]*aria-label=/);
  assert.match(main, /aria-current=/);
  assert.match(main, /<select\s+value=\{filter\}/);
  assert.match(main, /<label className="status-filter">/);
  assert.match(main, /<button[^>]*type="button"/);
});

test("keyboard focus and reduced-motion are defined without foreign runtime", () => {
  assert.match(styles, /:focus-visible/);
  assert.match(styles, /@media\(prefers-reduced-motion:reduce\)/);
  assert.match(styles, /\.spin\{animation:none\}/);
  for (const packageName of ["tailwindcss", "@radix-ui/react-dialog", "motion", "magicui", "shadcn"]) {
    assert.equal(Object.hasOwn(manifest.dependencies, packageName), false);
  }
});

test("source contract uses informational CSS primitives without creating an always-on visual effect", () => {
  assert.match(styles, /\.stat-tile\{/);
  assert.match(styles, /\.registry-panel/);
  assert.match(styles, /\.refresh-button/);
  assert.match(main, /disabled=\{busy\}/);
});
