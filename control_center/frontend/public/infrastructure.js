/* #294: separate per-host Atlas cards, read-only and no inferred measurements. */
(() => {
  "use strict";
  let button, panel, grid, active = false, pending = false, latest = null;
  const names = {hermes: "VPS Hermes", yfc: "VPS YFC"};
  const states = {online: "Данные актуальны", stale: "Данные устарели",
    unknown: "Ошибка снимка", not_connected: "Не подключён"};
  function el(tag, cls, parent, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = String(text);
    if (parent) parent.append(node);
    return node;
  }
  const percent = value => typeof value === "number" && Number.isFinite(value) &&
    value >= 0 && value <= 100 ? value : null;
  const number = value => typeof value === "number" && Number.isFinite(value) &&
    value >= 0 ? value : null;
  function amount(bytes) {
    if (number(bytes) === null) return "Нет данных";
    return (bytes / 1073741824).toLocaleString("ru-RU", {maximumFractionDigits: 2}) + " ГиБ";
  }
  function time(raw) {
    const d = new Date(raw);
    return Number.isNaN(d.getTime()) ? "Нет данных" :
      d.toLocaleString("ru-RU", {dateStyle: "short", timeStyle: "short"});
  }
  function meter(root, name, value, note) {
    const line = el("div", "infra294-metric", root);
    const label = el("div", "infra294-label", line);
    el("span", "", label, name);
    el("strong", "", label, percent(value) === null ? "Нет данных" : value + "%");
    const track = el("div", "infra294-track", line);
    track.setAttribute("role", "progressbar");
    track.setAttribute("aria-label", name);
    track.setAttribute("aria-valuemin", "0");
    track.setAttribute("aria-valuemax", "100");
    if (percent(value) !== null) {
      track.setAttribute("aria-valuenow", String(value));
      const fill = el("div", "infra294-fill", track);
      fill.style.width = String(value) + "%";
      if (value >= 90) fill.classList.add("infra294-critical");
      else if (value >= 75) fill.classList.add("infra294-high");
    }
    if (note) el("small", "", line, note);
  }
  function chart(root, raw, key, label) {
    root.replaceChildren();
    const rows = Array.isArray(raw?.samples) ? raw.samples : [];
    const points = rows.filter(item =>
      !Number.isNaN(Date.parse(item.observed_at)) && percent(item[key]) !== null);
    el("strong", "", root, label);
    if (!points.length) {
      el("p", "infra294-hint", root, "Пока нет подтверждённых измерений за этот период.");
      return;
    }
    const sample = points.filter((_, i) => i % Math.max(1, Math.ceil(points.length / 150)) === 0);
    if (sample[sample.length - 1] !== points[points.length - 1]) sample.push(points[points.length - 1]);
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 320 110");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", "История: " + label);
    const from = Date.parse(sample[0].observed_at);
    const end = Date.parse(sample[sample.length - 1].observed_at);
    const poly = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
    poly.setAttribute("fill", "none");
    poly.setAttribute("stroke", "#6cacef");
    poly.setAttribute("stroke-width", "2");
    poly.setAttribute("points", sample.map((p, index) => {
      const at = Date.parse(p.observed_at);
      const x = 8 + (end > from ? (at - from) / (end - from) : 0.5) * 304;
      const y = 100 - 0.85 * p[key];
      return x.toFixed(1) + "," + y.toFixed(1);
    }).join(" "));
    svg.append(poly); root.append(svg);
    el("small", "infra294-hint", root, points.length + " измерений. Последнее: " +
      time(points[points.length - 1].observed_at));
  }
  async function history(card, host, days, metric, target) {
    target.replaceChildren(el("p", "infra294-hint", null, "Загрузка истории…"));
    try {
      const r = await fetch("/api/infrastructure/history?host=" + host + "&days=" + days,
        {cache: "no-store", credentials: "same-origin"});
      if (!r.ok) throw Error("HTTP " + r.status);
      const result = await r.json();
      if (result.schema !== 1 || result.host !== host) throw Error("invalid");
      chart(target, result, metric, {"cpu": "CPU", "ram": "RAM", "disk": "Диск"}[metric]);
    } catch (_) {
      target.replaceChildren(el("p", "infra294-hint", null, "История недоступна."));
    }
  }
  function card(root, record) {
    const node = el("article", "infra294-card", root);
    const header = el("div", "infra294-card-head", node);
    const heading = el("div", "", header);
    el("span", "eyebrow", heading, "ИНФРАСТРУКТУРА / VPS");
    el("h3", "", heading, names[record.host]);
    const status = states[record.status] || "Состояние неизвестно";
    el("span", "infra294-state infra294-" + record.status, header, status);
    const current = record.status === "online", previous = record.status === "stale";
    if (!current && !previous) {
      el("p", "infra294-hint", node,
        record.host === "yfc" && record.status === "not_connected"
          ? "Сборщик YFC ещё не связан с Hermes. Цифры не подставляются."
          : "Нет достоверных измерений этого сервера.");
    } else {
      const m = record.metrics || {};
      if (previous) el("p", "infra294-hint", node,
        "Последние известные значения. Не считать текущей нагрузкой.");
      meter(node, "CPU", m.cpu_used_percent, "Фактическая загрузка CPU, не load average");
      meter(node, "RAM", m.ram_used_percent,
        amount(m.ram_used_bytes) + " из " + amount(m.ram_total_bytes));
      const swap = number(m.swap_total_bytes) && m.swap_total_bytes > 0 ?
        Math.round(1000 * m.swap_used_bytes / m.swap_total_bytes) / 10 : null;
      meter(node, "Swap", swap, amount(m.swap_used_bytes) + " из " + amount(m.swap_total_bytes));
      meter(node, "Диск /", m.disk_used_percent,
        amount(m.disk_used_bytes) + " из " + amount(m.disk_total_bytes));
      const details = el("div", "infra294-facts", node);
      el("span", "", details, "Load average (1/5/15): " +
        [m.load1, m.load5, m.load15].map(v =>
          number(v) === null ? "—" : v.toFixed(2)).join(" / "));
      el("span", "", details, "Uptime: " +
        (number(m.uptime_seconds) === null ? "—" : Math.floor(m.uptime_seconds / 3600) + " ч"));
    }
    el("small", "infra294-updated", node,
      "Последний снимок: " + (record.observed_at ? time(record.observed_at) : "нет"));
    const historyDetails = el("details", "infra294-history", node);
    el("summary", "", historyDetails, "История нагрузки");
    const toolbar = el("div", "infra294-toolbar", historyDetails);
    const period = el("select", "", toolbar);
    period.setAttribute("aria-label", "Период истории " + names[record.host]);
    for (const [n, name] of [["1", "24 часа"], ["7", "7 дней"], ["30", "30 дней"]]) {
      const option = el("option", "", period, name); option.value = n;
    }
    const metric = el("select", "", toolbar);
    metric.setAttribute("aria-label", "Метрика истории " + names[record.host]);
    for (const [n, name] of [["cpu", "CPU"], ["ram", "RAM"], ["disk", "Диск"]]) {
      const option = el("option", "", metric, name); option.value = n;
    }
    const container = el("div", "infra294-chart", historyDetails);
    const load = () => history(node, record.host, period.value, metric.value, container);
    historyDetails.addEventListener("toggle", () => {if (historyDetails.open) load();});
    period.addEventListener("change", () => {if (historyDetails.open) load();});
    metric.addEventListener("change", () => {if (historyDetails.open) load();});
  }
  function render(data) {
    if (!grid) return;
    grid.replaceChildren();
    if (!data || !Array.isArray(data.hosts)) {
      el("p", "infra294-hint", grid, "Сведения об инфраструктуре недоступны.");
      return;
    }
    for (const host of ["hermes", "yfc"]) {
      card(grid, data.hosts.find(x => x.host === host) ||
        {host, status: "not_connected"});
    }
  }
  async function refresh() {
    if (pending || !grid) return;
    pending = true;
    try {
      const r = await fetch("/api/infrastructure/hosts",
        {cache: "no-store", credentials: "same-origin"});
      if (!r.ok) throw Error("HTTP");
      const d = await r.json();
      if (d.schema !== 1 || d.mode !== "read_only") throw Error("schema");
      latest = d;
    } catch (_) { latest = null; }
    finally {pending = false; render(latest);}
  }
  function hide() {
    active = false;
    document.documentElement.classList.remove("infra294-active");
    if (panel) panel.hidden = true;
    if (button) {
      button.classList.remove("is-active");
      button.removeAttribute("aria-current");
    }
  }
  function show() {
    active = true;
    document.documentElement.classList.add("infra294-active");
    panel.hidden = false;
    button.classList.add("is-active");
    button.setAttribute("aria-current", "page");
    refresh();
  }
  function mount() {
    const nav = document.querySelector(".atlas-section-nav .nav-list");
    const target = document.querySelector(".center-area");
    if (!nav || !target) return;
    if (!button || !button.isConnected) {
      button = el("button", "nav-link infra294-nav", nav);
      button.type = "button";
      el("span", "nav-number", button, "08");
      el("span", "", button, "Инфраструктура");
      button.onclick = show;
    }
    if (!panel || !panel.isConnected) {
      panel = el("section", "infra294-panel", target);
      panel.hidden = !active;
      panel.setAttribute("aria-label", "Мониторинг VPS Hermes и YFC");
      const head = el("div", "infra294-head", panel);
      const title = el("div", "", head);
      el("span", "eyebrow", title, "H-15 / #294");
      el("h2", "", title, "Инфраструктура");
      el("p", "infra294-hint", title, "Каждый VPS отслеживается отдельно. Нет данных - не значит нулевая нагрузка.");
      const reload = el("button", "infra294-refresh", head, "Обновить");
      reload.type = "button"; reload.onclick = refresh;
      grid = el("div", "infra294-grid", panel);
      render(latest);
    }
  }
  document.addEventListener("click", event => {
    if (active && event.target.closest(".nav-link:not(.infra294-nav),.atlas-nav button")) hide();
  }, true);
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", mount, {once: true});
  else mount();
  new MutationObserver(mount).observe(document.body, {subtree: true, childList: true});
  window.setInterval(() => {if (active && !document.hidden) refresh();}, 60000);
})();
