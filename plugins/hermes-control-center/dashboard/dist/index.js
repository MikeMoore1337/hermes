(function () {
  "use strict";

  const SDK = window.__HERMES_PLUGIN_SDK__;
  const registry = window.__HERMES_PLUGINS__;
  if (!SDK || !SDK.React || !SDK.fetchJSON || !registry) return;

  const React = SDK.React;
  const h = React.createElement;
  const labels = Object.freeze({
    active: "Работает",
    inactive: "Неактивен",
    failed: "Ошибка",
    blocked: "Не допущен",
    unknown: "Нет данных",
    unexpected_active: "Запущен без допуска"
  });

  function ServiceRow(props) {
    const s = props.service;
    return h("li", {
      key: s.id,
      className: "flex justify-between items-start gap-4 py-3 border-b border-border"
    }, [
      h("div", {key: "identity"}, [
        h("div", {className: "font-medium text-sm", key: "name"}, String(s.name || s.id)),
        h("div", {className: "text-xs text-muted-foreground", key: "unit"}, String(s.unit || ""))
      ]),
      h("span", {key: "state", className: "text-sm font-semibold text-nowrap"},
        labels[s.state] || labels.unknown)
    ]);
  }

  function ControlCenter() {
    const [snapshot, setSnapshot] = React.useState(null);
    const [error, setError] = React.useState("");

    React.useEffect(function () {
      let active = true;
      async function refresh() {
        try {
          // SDK.fetchJSON supplies the Hermes Dashboard session authorization.
          const value = await SDK.fetchJSON("/api/plugins/hermes-control-center/overview");
          if (value.schema !== 1 || value.mode !== "read_only" ||
              !Array.isArray(value.services)) {
            throw new Error("Invalid snapshot");
          }
          const recorded = Date.parse(value.generated_at);
          if (!Number.isFinite(recorded) || recorded - Date.now() > 120000 ||
              Date.now() - recorded > 180000) {
            throw new Error("Stale snapshot");
          }
          if (active) {setSnapshot(value); setError("");}
        } catch (_) {
          if (active) {
            setSnapshot(null);
            setError("Состояние недоступно. Требуется проверить сбор снимка на сервере.");
          }
        }
      }
      refresh();
      const id = setInterval(refresh, 60000);
      return function () { active = false; clearInterval(id); };
    }, []);

    const states = snapshot ? snapshot.services : [];
    const healthy = states.filter(s => s.state === "active").length;
    const attention = states.filter(s =>
      ["failed", "unknown", "unexpected_active"].includes(s.state)).length;
    const Card = SDK.components && SDK.components.Card;
    const CardContent = SDK.components && SDK.components.CardContent;
    const rows = h("ul", {className: "divide-y divide-border"}, states.map(s =>
      h(ServiceRow, {key: s.id, service: s})));
    const listing = Card && CardContent
      ? h(Card, null, h(CardContent, {className: "pt-4"}, rows))
      : h("section", {className: "rounded-lg border p-5"}, rows);

    return h("main", {className: "max-w-5xl mx-auto p-4 space-y-5"}, [
      h("header", {key:"head", className:"space-y-2"}, [
        h("h1", {key:"title", className:"text-2xl font-bold"}, "Центр управления Hermes"),
        h("p", {key:"summary", className:"text-sm text-muted-foreground"},
          "Безопасный обзор существующих служб. Режим только для чтения.")
      ]),
      h("section", {key:"meta", className:"text-sm"}, snapshot
        ? "Активны: " + healthy + " · Требуют внимания: " + attention +
          " · Снимок: " + new Date(snapshot.generated_at).toLocaleString("ru-RU")
        : error || "Загрузка состояния…"),
      snapshot ? h("div", {key:"rows"}, listing) : null,
      h("p", {key:"policy",className:"text-sm text-amber-600"},
        "Постоянный AI Agent: NO-GO. Запуск, управление инструментами и изменение настроек здесь недоступны.")
    ]);
  }

  registry.register("hermes-control-center", ControlCenter);
})();
