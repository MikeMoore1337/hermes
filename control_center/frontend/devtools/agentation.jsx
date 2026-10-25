// Local opt-in only: npm install --no-save --package-lock=false --ignore-scripts agentation@3.1.2
// This file is loaded from Vite serve, never from control_center/web production.
import {Agentation} from "agentation";
import {createElement} from "react";
import {createRoot} from "react-dom/client";

const loopback = ["127.0.0.1", "localhost", "::1", "[::1]"].includes(window.location.hostname);
const desktop = window.matchMedia("(min-width: 768px)").matches;

if (loopback && desktop) {
  const mount = document.createElement("div");
  mount.id = "hermes-local-agentation";
  document.body.append(mount);
  // Copy is explicit. No endpoint, webhook, session sync or silent submission.
  createRoot(mount).render(createElement(Agentation, {
    appName: "Hermes Control Center local UI",
    enableKeyboardShortcuts: false,
    identifyingAttributes: ["data-testid", "data-qa"],
  }));
}
