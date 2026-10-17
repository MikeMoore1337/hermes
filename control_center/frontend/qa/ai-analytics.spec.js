import {test,expect} from "@playwright/test";
import {mkdirSync} from "node:fs";
import {resolve} from "node:path";

const output=resolve("../../docs/ux/evidence/h15-ai-analytics");
const snapshot={schema:1,mode:"read_only",generated_at:new Date().toISOString(),services:[]};
const observed={schema:1,source:"codex-local-rollout-jsonl",period:"7d",
 quality:"partial",observed_at:"2026-10-18T00:00:00Z",sessions:2,
 completed_turns:3,duration_seconds:600,tokens:{input:1500,output:400,cached_input:600,total:1900},
 api_equivalent_usd:0.007,actual_spend_usd:null,price_version:"2026-10-18-v1",
 pricing_coverage:1,models:[{name:"gpt-5.3-codex",input:1500,output:400,cached:600}],
 projects:[{name:"Hermes",input:1500,output:400,cached:600}],tasks:[],
 daily:[{date:"2026-10-18",input:1500,output:400,cached:600}],
 invalid_events:1,incomplete_files:0};

async function setup(page,empty=false){
 await page.route("**/api/overview",route=>route.fulfill({status:200,contentType:"application/json",
   body:JSON.stringify({...snapshot,generated_at:new Date().toISOString()})}));
 await page.route("**/api/analytics/codex?*",route=>route.fulfill({status:200,contentType:"application/json",
   body:JSON.stringify(empty?{...observed,quality:"unknown",sessions:null,completed_turns:null,
    duration_seconds:null,tokens:{input:null,output:null,cached_input:null,total:null},
    api_equivalent_usd:null,models:[],projects:[],daily:[]}:observed)}));
}

for(const width of [393,1440]){
 test("AI Usage Analytics Atlas desktop/mobile visual gate "+width,async({page})=>{
  await page.setViewportSize({width,height:900});
  await setup(page);
  await page.goto("/");
  await page.getByRole("button",{name:"AI Usage Analytics"}).click();
  const panel=page.getByRole("region",{name:"AI Usage Analytics"});
  await expect(panel).toBeVisible();
  await expect(panel.locator("[data-summary]").getByText("1 900",{exact:true})).toBeVisible();
  await expect(panel.getByText("Нет данных",{exact:true}).first()).toBeVisible();
  await expect(panel.locator("[data-breakdown]").getByText("Hermes",{exact:true})).toBeVisible();
  await expect(panel.locator("[data-breakdown]").getByText("gpt-5.3-codex",{exact:true})).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1)).toBe(false);
  mkdirSync(output,{recursive:true});
  await page.screenshot({path:resolve(output,"analytics-"+width+".png"),fullPage:true});
  await page.locator(".atlas-section-nav").getByRole("button",{name:"Обзор"}).click();
  await expect(panel).toBeHidden();
 });
}

test("Unknown usage is never represented as observed zero",async({page})=>{
 await setup(page,true);await page.goto("/");
 await page.getByRole("button",{name:"AI Usage Analytics"}).click();
 const panel=page.getByRole("region",{name:"AI Usage Analytics"});
 await expect(panel.getByText("Нет данных",{exact:true}).first()).toBeVisible();
 await expect(panel.getByText("0",{exact:true})).toHaveCount(0);
 await expect(panel.getByText("Неизвестно",{exact:true})).toBeVisible();
});

test("Period and read-only filters do not execute Codex",async({page})=>{
 await setup(page);await page.goto("/");
 await page.getByRole("button",{name:"AI Usage Analytics"}).click();
 const panel=page.getByRole("region",{name:"AI Usage Analytics"});
 await panel.getByLabel("Период").selectOption("24h");
 await expect(panel.locator("[data-summary]").getByText("1 900",{exact:true})).toBeVisible();
 await panel.getByLabel("Модель").selectOption("gpt-5.3-codex");
 await panel.getByLabel("Показатель").selectOption("cycles");
 await expect(panel.getByText("Наблюдаемая активность")).toBeVisible();
 await expect(panel.getByRole("button")).toHaveCount(1);
});
