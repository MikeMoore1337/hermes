import {test,expect} from "@playwright/test";

async function openOrbitWidget(page,label){
 if((page.viewportSize()?.width||1280)<=700){
  const more=page.locator(".orbit-app-mobilebar").getByRole("button",{name:"Ещё"});
  if(await more.getAttribute("aria-expanded")!=="true")await more.click();
 }
 await page.getByRole("button",{name:label,exact:true}).click();
}

// #179: deterministic semantic contracts without production API, credentials or model calls.
test.use({serviceWorkers:"block"});

async function overview(page){
 await page.route("**/api/overview",route=>route.fulfill({
  status:200,contentType:"application/json",
  body:JSON.stringify({schema:1,mode:"read_only",
   generated_at:new Date().toISOString(),services:[]})
 }));
}

async function analytics(page,completed){
 await page.route("**/api/analytics/codex?*",route=>route.fulfill({
  status:200,contentType:"application/json",
  body:JSON.stringify({schema:1,source:"codex-local-rollout-jsonl",
   quality:completed===null?"unknown":"partial",
   completed_turns:completed,tokens:{input:null,output:null,cached_input:null,total:null},
   sessions:null,duration_seconds:null,api_equivalent_usd:null,
   models:[],projects:[],daily:[]})
 }));
}

test("unknown AI cycles remain unknown instead of a fabricated zero",async({page})=>{
 await overview(page);await analytics(page,null);
 await page.goto("/");
 await openOrbitWidget(page,"AI Usage Analytics");
 const panel=page.getByRole("region",{name:"AI Usage Analytics"});
 await panel.getByLabel("Показатель").selectOption("cycles");
 await expect(panel.getByText("Число завершённых циклов неизвестно.")).toBeVisible();
 await expect(panel.locator("[data-chart] .ai272-row")).toHaveCount(0);
 await expect(panel.locator("[data-status]")).toHaveText("Неизвестно");
});

test("a confirmed zero completed AI cycles stays a real zero",async({page})=>{
 await overview(page);await analytics(page,0);
 await page.goto("/");
 await openOrbitWidget(page,"AI Usage Analytics");
 const panel=page.getByRole("region",{name:"AI Usage Analytics"});
 await panel.getByLabel("Показатель").selectOption("cycles");
 await expect(panel.locator("[data-chart] .ai272-row")).toHaveCount(1);
 await expect(panel.locator("[data-chart] .ai272-row strong")).toHaveText("0");
 await expect(panel.getByText("Число завершённых циклов неизвестно.")).toHaveCount(0);
});

test("same CPU label identifies Hermes and YFC hosts, history identifies its owner",async({page})=>{
 await overview(page);
 const hosts=["hermes","yfc"].map((host,i)=>({host,status:"online",
  observed_at:new Date().toISOString(),metrics:{
   cpu_used_percent:23+i*47,ram_used_percent:42,disk_used_percent:53,
   ram_used_bytes:400000000,ram_total_bytes:1000000000,
   disk_used_bytes:500000000,disk_total_bytes:1000000000
  }}));
 await page.route("**/api/infrastructure/hosts",route=>route.fulfill({
  status:200,contentType:"application/json",
  body:JSON.stringify({schema:1,mode:"read_only",hosts})
 }));
 await page.route("**/api/infrastructure/history?*",route=>{
  const host=new URL(route.request().url()).searchParams.get("host");
  return route.fulfill({status:200,contentType:"application/json",
   body:JSON.stringify({schema:1,host,samples:[
    {observed_at:new Date(Date.now()-60000).toISOString(),cpu:10,ram:42,disk:53},
    {observed_at:new Date().toISOString(),cpu:20,ram:43,disk:54}
   ]})});
 });
 await page.goto("/");
 await openOrbitWidget(page,"Инфраструктура");
 const region=page.getByRole("region",{name:"Мониторинг VPS Hermes и YFC"});
 const hermes=region.getByRole("progressbar",{name:"VPS Hermes: CPU"});
 const yfc=region.getByRole("progressbar",{name:"VPS YFC: CPU"});
 await expect(hermes).toHaveAttribute("aria-valuenow","23");
 await expect(yfc).toHaveAttribute("aria-valuenow","70");
 await region.locator(".infra294-card").first().locator("summary").click();
 await expect(region.getByRole("img",{name:"История VPS Hermes: CPU"})).toBeVisible();
 await expect(region.getByRole("img",{name:"История VPS YFC: CPU"})).toHaveCount(0);
});

test("unified Codex and provider progressbars retain accessible usage semantics",async({page})=>{
 await overview(page);
 const window=(label,used,remaining)=>({
  label,metric:"provider_quota",unit:"percent",quota_limit:null,
  used:null,remaining:null,used_percent:used,remaining_percent:remaining,
  reset_at_utc:null,source_kind:"official_api"
 });
 await page.route("**/api/providers/codex",route=>route.fulfill({
  status:200,contentType:"application/json",
  body:JSON.stringify({schema:1,source:"codex-app-server",status:"low",
   observed_at:new Date().toISOString(),limits:[{limit_id:"codex",status:"low",
    windows:[{duration_minutes:300,remaining_percent:19,resets_at:null}]}]})
 }));
 await page.route("**/api/providers/registry",route=>route.fulfill({
  status:200,contentType:"application/json",
  body:JSON.stringify({schema:1,read_only:true,providers:[
   {id:"github_api",status:"ok",notes:"per_token_rate_limit_collected",
    windows:[window("API core",25,75)]},
   {id:"cloudflare_workers_ai",status:"unknown",notes:"account_usage_unavailable",
    windows:[window("Неизвестный остаток",null,null)]}
  ]})
 }));
 await page.goto("/");
 await openOrbitWidget(page,"Квоты и инструменты");
 const codex=page.getByRole("region",{name:"Лимиты Codex"});
 const codexMeter=codex.getByRole("progressbar",{name:"Осталось в окне 5 часов"});
 await expect(codexMeter).toHaveAttribute("aria-valuenow","19");
 await expect(codex.getByText("19% осталось")).toBeVisible();
 const providers=page.getByRole("region",{name:"Квоты и инструменты Hermes"});
 const github=providers.getByRole("progressbar",{name:"GitHub API: API core"});
 await expect(github).toHaveAttribute("aria-valuenow","25");
 await expect(github).toHaveAttribute("aria-valuetext","Использовано: 25%; осталось: 75%");
 await expect(providers.locator('[data-provider="desktop_commander"]')).toHaveCount(0);
 await expect(providers.locator('[data-provider="codex"]')).toHaveCount(0);
 await expect(providers.locator('[data-provider="cloudflare_workers_ai"] [role="progressbar"]')).toHaveCount(0);
});
