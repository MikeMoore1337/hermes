/**
 * Optional local Vite-only annotation helper. Nothing enters the deployed web bundle.
 * Never auto-installs a package or connects an MCP server.
 */
export function agentationDevelopmentHtml(html, enabled) {
  if (!enabled) return html;
  return {
    html,
    tags: [
      {
        tag: "script",
        attrs: { type: "module", src: "/devtools/agentation.jsx" },
        injectTo: "body",
      },
    ],
  };
}

export function agentationDevelopmentPlugin() {
  return {
    name: "hermes-local-agentation",
    apply: "serve",
    transformIndexHtml(html) {
      return agentationDevelopmentHtml(html, process.env.HERMES_AGENTATION === "1");
    },
  };
}
