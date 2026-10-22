import { test, expect } from "@playwright/test";

// Browser evidence for the approved Hermes Control Center UI. All monitoring
// values below are synthetic: never use owner cookies, tokens or production API.
test.use({ serviceWorkers: "block" });

// Fail closed before browser traffic reaches any account, OAuth callback,
// external host or non-overview API. Evidence may contain only synthetic data.
async function isolateEvidenceNetwork(page) {
  const denied = [];
  await page.route("**/*", (route) => {
    const url = new URL(route.request().url());
    const local = url.protocol === "http:" && url.hostname === "127.0.0.1" && url.port === "9133";
    if (!local || url.pathname.startsWith("/auth/") || url.pathname.startsWith("/api/auth/")) {
      denied.push(local ? "oauth_request" : "external_request");
      return route.abort("blockedbyclient");
    }
    if (url.pathname.startsWith("/api/") && url.pathname !== "/api/overview") {
      // Unknown APIs are intentionally unavailable, never proxied to the owner VPS.
      return route.fulfill({
        status: 503, contentType: "application/json",
        body: JSON.stringify({ error: "synthetic_api_unavailable" }),
      });
    }
    return route.continue();
  });
  return denied;
}

async function syntheticOverview(page, responseStatus = 200) {
  await page.route("**/api/overview", (route) => route.fulfill({
    status: responseStatus,
    contentType: "application/json",
    body: responseStatus === 200 ? JSON.stringify({
      schema: 1, mode: "read_only", generated_at: new Date().toISOString(),
      services: [
        { id: "ops", name: "Ops Watch", unit: "hermes-ops-watch.timer", state: "active", kind: "schedule" },
        { id: "qa", name: "QA Advisor", unit: "hermes-qa-watch.timer", state: "failed", kind: "schedule" },
      ],
      agent_policy: "Synthetic QA evidence. Resident agent not enabled.",
    }) : "synthetic unavailable",
  }));
}

test("visual evidence: synthetic Control Center across representative viewports", async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  const pageErrors = [];
  const observations = [];
  const denied = await isolateEvidenceNetwork(page);
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await syntheticOverview(page);
  await page.emulateMedia({ reducedMotion: "reduce" });

  for (const width of [320, 393, 768, 1440]) {
    const viewport = { width, height: width < 768 ? 844 : 900 };
    await page.setViewportSize(viewport);
    await page.goto("/");
    await expect(page.getByRole("main")).toHaveCount(1);
    await expect(page.getByRole("navigation", { name: "Разделы управления" })).toHaveCount(1);
    const search = page.getByRole("textbox", { name: "Поиск по службам" });
    await expect(search).toBeVisible();
    await expect(page.getByRole("row", { name: /Ops Watch/ })).toBeVisible();
    await search.fill("QA");
    await expect(page.getByRole("row", { name: /Ops Watch/ })).toHaveCount(0);
    await expect(page.getByRole("row", { name: /QA Advisor/ })).toBeVisible();
    await search.fill("");
    await expect(page.getByRole("row", { name: /Ops Watch/ })).toBeVisible();
    const layout = await page.evaluate(() => ({
      viewport: innerWidth, document: document.documentElement.scrollWidth,
    }));
    expect(layout.document, `Horizontal overflow at ${width}px`).toBeLessThanOrEqual(layout.viewport + 1);
    await testInfo.attach(`control-center-synthetic-${width}.png`, {
      body: await page.screenshot({ fullPage: true, animations: "disabled" }),
      contentType: "image/png",
    });
    observations.push({
      route: "/", state: "synthetic-operator-search-reset", viewport,
      reducedMotion: "reduce", dataSource: "synthetic", layout,
    });
  }

  await testInfo.attach("visual-evidence-manifest.json", {
    body: JSON.stringify({
      schema: 1, evidence_kind: "synthetic_only", observations,
      denied_network_attempts: denied, pageErrors,
    }, null, 2),
    contentType: "application/json",
  });
  expect(pageErrors, "Uncaught browser errors").toEqual([]);
  expect(denied, "Unexpected OAuth or external network request").toEqual([]);
});

test("visual evidence: unavailable overview is explicit and contains no synthetic healthy row", async ({ page }, testInfo) => {
  const pageErrors = [];
  const denied = await isolateEvidenceNetwork(page);
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await syntheticOverview(page, 503);
  await page.setViewportSize({ width: 393, height: 844 });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/");
  await expect(page.getByRole("alert")).toContainText(/503/);
  await expect(page.getByRole("row", { name: /Ops Watch/ })).toHaveCount(0);
  await testInfo.attach("control-center-synthetic-api-503.png", {
    body: await page.screenshot({ fullPage: true, animations: "disabled" }),
    contentType: "image/png",
  });
  expect(pageErrors, "Uncaught browser errors").toEqual([]);
  expect(denied, "Unexpected OAuth or external network request").toEqual([]);
});

test("visual evidence: login preview remains non-interactive at mobile and desktop widths", async ({ page }, testInfo) => {
  const denied = await isolateEvidenceNetwork(page);
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.emulateMedia({ reducedMotion: "reduce" });
  for (const width of [393, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/?preview=login");
    await expect(page.getByRole("heading", { name: "Вход в систему" })).toBeVisible();
    await expect(page.getByRole("button", { name: /Войти через GitHub/ })).toBeDisabled();
    await expect(page.getByRole("table")).toHaveCount(0);
    const layout = await page.evaluate(() => ({
      viewport: innerWidth, document: document.documentElement.scrollWidth,
    }));
    expect(layout.document, "Login overflow").toBeLessThanOrEqual(layout.viewport + 1);
    await testInfo.attach(`control-center-synthetic-login-${width}.png`, {
      body: await page.screenshot({ fullPage: true, animations: "disabled" }),
      contentType: "image/png",
    });
  }
  expect(denied, "Unexpected OAuth or external network request").toEqual([]);
  expect(errors, "Uncaught browser errors").toEqual([]);
});
