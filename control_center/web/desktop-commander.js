/* Read-only Desktop Commander widget; no dependencies or inline scripts. */
(() => {
  "use strict";
  if (document.getElementById("dc-monitor")) return;
  const wrap = document.createElement("div");
  wrap.id = "dc-monitor";
  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.className = "dc-toggle";
  toggle.textContent = "Устройства";
  toggle.setAttribute("aria-expanded", "false");
  toggle.setAttribute("aria-controls", "dc-monitor-panel");
  const panel = document.createElement("section");
  panel.id = "dc-monitor-panel";
  panel.className = "dc-panel";
  panel.hidden = true;
  panel.setAttribute("aria-label", "Состояние Desktop Commander");
  const head = document.createElement("div");
  head.className = "dc-head";
  const title = document.createElement("h2");
  title.textContent = "Desktop Commander";
  const close = document.createElement("button");
  close.type = "button";
  close.className = "dc-close";
  close.textContent = "Закрыть";
  head.append(title, close);
  const description = document.createElement("p");
  description.className = "dc-hint";
  description.textContent = "Удалённые устройства и облачный лимит. Статус Online не подтверждает возможность выполнения команд.";
  const content = document.createElement("div");
  content.className = "dc-status";
  content.setAttribute("aria-live", "polite");
  const actions = document.createElement("div");
  actions.className = "dc-actions";
  const refresh = document.createElement("button");
  refresh.type = "button";
  refresh.textContent = "Обновить";
  const details = document.createElement("a");
  details.href = "https://mcp.desktopcommander.app/usage";
  details.target = "_blank";
  details.rel = "noopener noreferrer";
  details.textContent = "Кабинет Usage ↗";
  actions.append(refresh, details);
  panel.append(head, description, content, actions);
  wrap.append(toggle, panel);
  document.body.append(wrap);
  let pending = false;
  let nextPoll = 0;
  function elt(tag, value, css) {
    const node = document.createElement(tag);
    if (value !== undefined) node.textContent = value;
    if (css) node.className = css;
    return node;
  }
  function render(data) {
    content.replaceChildren();
    const labels = {
      exhausted: "Лимит исчерпан", monitored: "Метаданные получены",
      stale: "Данные устарели", unknown: "Квота неизвестна",
      unavailable: "Remote MCP недоступен", auth_required: "Нужна авторизация",
      not_configured: "Сбор статистики не подключён"
    };
    const status = data && labels[data.status] ? data.status : "unknown";
    content.append(elt("div", labels[status], "dc-state dc-" + status));
    content.append(elt("p", data && Number.isInteger(data.quota_remaining_percent)
      ? data.quota_remaining_percent + "% облачной квоты осталось"
      : "Точный остаток облачной квоты неизвестен", "dc-metric"));
    if (data && Array.isArray(data.devices) && data.devices.length) {
      const list = elt("ul", undefined, "dc-devices");
      data.devices.slice(0, 16).forEach(device => {
        const row = elt("li");
        const name = elt("strong", typeof device.name === "string" ? device.name : "Неизвестное устройство");
        const state = ["online", "offline"].includes(device.state) ? device.state : "unknown";
        const indicator = elt("span", state === "online" ? "Online" : state === "offline" ? "Offline" : "Нет данных",
                              "dc-device-state dc-" + state);
        row.append(name, indicator);
        list.append(row);
      });
      content.append(list);
    } else {
      content.append(elt("p", "Список устройств недоступен.", "dc-hint"));
    }
    content.append(elt("p",
      status === "exhausted"
        ? "Удалённые команды заблокированы квотой. Локальный MCP на VPS от этой квоты не зависит."
        : "Remote execution: не проверено. Онлайн-статус и ping недостаточны для допуска задач.",
      "dc-hint"));
    if (data && data.observed_at && !Number.isNaN(Date.parse(data.observed_at))) {
      content.append(elt("small", "Последний снимок: " +
        new Date(data.observed_at).toLocaleString("ru-RU"), "dc-time"));
    }
  }
  async function load(force = false) {
    if (pending || (!force && Date.now() < nextPoll)) return;
    pending = true;
    refresh.disabled = true;
    try {
      const response = await fetch("/api/providers/desktop-commander", {
        cache: "no-store", credentials: "same-origin"
      });
      if (!response.ok) throw new Error("HTTP " + response.status);
      render(await response.json());
      nextPoll = Date.now() + 60000;
    } catch (_) {
      content.replaceChildren(elt("p", "Не удалось получить защищённый снимок.", "dc-error"));
      nextPoll = Date.now() + 30000;
    } finally {
      pending = false;
      refresh.disabled = false;
    }
  }
  function setOpen(open) {
    panel.hidden = !open;
    toggle.setAttribute("aria-expanded", String(open));
    if (open) { load(); close.focus(); }
    else toggle.focus();
  }
  toggle.addEventListener("click", () => setOpen(panel.hidden));
  close.addEventListener("click", () => setOpen(false));
  refresh.addEventListener("click", () => load(true));
  document.addEventListener("keydown", event => {
    if (event.key === "Escape" && !panel.hidden) setOpen(false);
  });
  window.setInterval(() => {
    if (!panel.hidden && !document.hidden) load();
  }, 60000);
})();
