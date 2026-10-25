import test from "node:test";
import assert from "node:assert/strict";
import {agentationDevelopmentHtml, agentationDevelopmentPlugin} from "../devtools/agentation-dev-plugin.js";

test("Agentation off preserves normal HTML without any script injection", () => {
  const html = "<html><body></body></html>";
  assert.equal(agentationDevelopmentHtml(html, false), html);
});

test("Agentation on injects only a Vite dev module", () => {
  assert.deepEqual(agentationDevelopmentHtml("<html></html>", true), {
    html: "<html></html>",
    tags: [{tag:"script",attrs:{type:"module",src:"/devtools/agentation.jsx"},injectTo:"body"}],
  });
});

test("Agentation plugin applies only to local Vite serve, not production build", () => {
  const plugin = agentationDevelopmentPlugin();
  assert.equal(plugin.name, "hermes-local-agentation");
  assert.equal(plugin.apply, "serve");
});
