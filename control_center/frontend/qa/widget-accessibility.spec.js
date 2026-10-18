import {test,expect} from "@playwright/test";

// #179 screen-reader-facing contracts. All API responses are synthetic, never production.
test.use({serviceWorkers:"block"});

async function overview(page) {
 await page.route("**/api/overview",route=>route.fulfill({
  status:200,contentType:"application/json",
  body:JSON.stringify({
   schema:1,mode:"read_only",generated_at:new Date().toISOString(),
   services:[],agent_policy:"Полный агент не допущен"
  })
 }));
}

test("Desktop Commander: status transitions are separate from verbose content; Escape restores focus",async({page})=>{
 await overview(page);
 let remaining=70;
 await page.route("**/api/providers/desktop-commander",route=>route.fulfill({
  status:200,contentType:"application/json",
  body:JSON.stringify({status:"stale",quota_remaining_percent:remaining,
   devices:[{name:"Synthetic device",state:"offline"}],
   observed_at:new Date().toISOString()})
 }));
 await page.goto("/");
 const toggle=page.getByRole("button",{name:"Устройства"});
 await toggle.focus();await toggle.press("Enter");
 const panel=page.getByRole("region",{name:"Состояние Desktop Commander"});
 await expect(panel).toBeVisible();
 await expect(toggle).toHaveAttribute("aria-expanded","true");
 await expect(panel.getByRole("status")).toHaveText("Desktop Commander: Данные устарели");
 await expect(panel.locator(".dc-status")).not.toHaveAttribute("aria-live",/./);
 await expect(panel.locator(".dc-chart")).not.toHaveAttribute("aria-live",/./);
 await expect(panel.getByText("Synthetic device")).toBeVisible();
 remaining=30;
 await panel.getByRole("button",{name:"Обновить"}).click();
 await expect(panel.getByText("30% облачной квоты осталось")).toBeVisible();
 await expect(panel.getByRole("status")).toHaveText("Desktop Commander: Данные устарели");
 await page.keyboard.press("Escape");
 await expect(panel).toBeHidden();
 await expect(toggle).toHaveAttribute("aria-expanded","false");
 await expect(toggle).toBeFocused();
});

test("VPS metrics: missing measurement is a named indeterminate progressbar",async({page})=>{
 await overview(page);
 await page.route("**/api/infrastructure/hosts",route=>route.fulfill({
  status:200,contentType:"application/json",
  body:JSON.stringify({schema:1,mode:"read_only",hosts:[
   {host:"hermes",status:"online",metrics:{cpu_used_percent:null}},
   {host:"yfc",status:"not_connected"}]})
 }));
 await page.goto("/");
 const button=page.getByRole("button",{name:"Инфраструктура"});
 await button.focus();await button.press("Enter");
 const panel=page.getByRole("region",{name:"Мониторинг VPS Hermes и YFC"});
 await expect(panel).toBeVisible();
 await expect(panel.getByRole("status")).toContainText("VPS YFC: Не подключён");
 const cpu=panel.locator(".infra294-card").first().getByRole("progressbar",{name:"CPU"});
 await expect(cpu).toHaveAttribute("aria-valuetext","Нет данных");
 await expect(cpu).not.toHaveAttribute("aria-valuenow",/./);
 await expect(panel.getByText("Нет данных",{exact:true}).first()).toBeVisible();
});

test("Provider quota transition announces named status, not a fabricated availability",async({page})=>{
 await overview(page);
 let providerStatus="unknown";
 await page.route("**/api/providers/registry",route=>route.fulfill({
  status:200,contentType:"application/json",
  body:JSON.stringify({schema:1,read_only:true,providers:[
   {id:"codex",status:providerStatus,windows:[],notes:"usage_unavailable"},
   {id:"desktop_commander",status:"not_connected",windows:[],notes:"not_configured"}]})
 }));
 await page.goto("/");
 await page.getByRole("button",{name:"Квоты и инструменты"}).click();
 const panel=page.getByRole("region",{name:"Квоты и инструменты Hermes"});
 await expect(panel).toBeVisible();
 const announcement=panel.getByRole("status");
 await expect(announcement).toContainText("Codex / ChatGPT: Нет подтверждённых данных");
 await expect(announcement).toContainText("Desktop Commander: Не подключено");
 providerStatus="auth_required";
 await panel.getByRole("button",{name:"Обновить"}).click();
 await expect(announcement).toContainText("Codex / ChatGPT: Нужна авторизация");
 await expect(panel.locator(".quota295-card[data-provider='codex']")).not.toContainText("Доступно");
});

test("AI usage status is announced and exposes pending work via aria-busy",async({page})=>{
 await overview(page);
 await page.route("**/api/analytics/codex?*",route=>route.fulfill({
  status:200,contentType:"application/json",
  body:JSON.stringify({
   schema:1,source:"codex-local-rollout-jsonl",quality:"partial",
   tokens:{total:100,input:80,output:20,cached_input:0},
   sessions:1,completed_turns:1,duration_seconds:30,
   models:[],projects:[],daily:[]
  })
 }));
 await page.goto("/");
 await page.getByRole("button",{name:"AI Usage Analytics"}).click();
 const panel=page.getByRole("region",{name:"AI Usage Analytics"});
 await expect(panel.getByRole("status")).toHaveText("Частично");
 await expect(panel).not.toHaveAttribute("aria-busy",/./);
});
