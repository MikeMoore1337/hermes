import {test,expect} from "@playwright/test";

// H-15 #179: no production calls, OAuth requests, real systemd state or privileged operations.
test.use({serviceWorkers:"block"});
const services=[
 {id:"ops",name:"Ops Watch",unit:"hermes-ops-watch.timer",state:"active",kind:"schedule"},
 {id:"qa",name:"QA Advisor",unit:"hermes-qa-watch.timer",state:"failed",kind:"schedule"},
 {id:"agent",name:"Полный AI Agent (без допуска)",unit:"hermes-agent-sandbox.service",state:"blocked",kind:"restricted"}
];
async function mock(page){
 await page.route("**/api/overview",route=>route.fulfill({status:200,contentType:"application/json",
  body:JSON.stringify({schema:1,mode:"read_only",generated_at:new Date().toISOString(),
   services,agent_policy:"Полный AI Agent не допущен"})}));
}
for(const width of [320,393,768,1440]){
 test(`native register table retains column names in accessibility tree at ${width}px`,async({page})=>{
  await page.setViewportSize({width,height:850});
  await mock(page);await page.goto("/");
  const registry=page.getByRole("table",{name:"Реестр системных служб и компонентов"});
  await expect(registry).toHaveCount(1);
  for(const heading of ["Служба / единица","Состояние","Режим","Источник"]){
   await expect(registry.getByRole("columnheader",{name:heading})).toHaveCount(1);
  }
  await expect(registry.getByRole("row",{name:/Ops Watch/})).toContainText("Работает");
  await expect(registry.getByRole("row",{name:/Полный AI Agent/})).toContainText("Не допущен");
  const overflow=await page.evaluate(()=>document.documentElement.scrollWidth-innerWidth);
  expect(overflow,"No whole-document horizontal overflow").toBeLessThanOrEqual(1);
 });
}

test("both navigation sets expose same current view and remain keyboard-operable",async({page})=>{
 await mock(page);await page.goto("/");
 const header=page.getByRole("navigation",{name:"Основные разделы"});
 const secondary=page.getByRole("navigation",{name:"Разделы управления"});
 await expect(header.getByRole("button",{name:"Обзор"})).toHaveAttribute("aria-current","page");
 await expect(secondary.getByRole("button",{name:"Обзор"})).toHaveAttribute("aria-current","page");
 const qa=header.getByRole("button",{name:"QA и CI"});
 await qa.focus();await qa.press("Enter");
 await expect(qa).toHaveAttribute("aria-current","page");
 await expect(secondary.getByRole("button",{name:"QA и CI"})).toHaveAttribute("aria-current","page");
 await expect(header.getByRole("button",{name:"Обзор"})).not.toHaveAttribute("aria-current",/./);
 await expect(page.getByRole("table",{name:"Реестр системных служб и компонентов"})).toHaveCount(1);
 await expect(page.getByRole("row",{name:/Ops Watch/})).toHaveCount(0);
});

test("stale and empty snapshots keep table caption without invented data",async({page})=>{
 await page.route("**/api/overview",route=>route.fulfill({status:503,body:"unavailable"}));
 await page.goto("/");
 await expect(page.getByRole("alert")).toContainText("503");
 const table=page.getByRole("table",{name:"Реестр системных служб и компонентов"});
 await expect(table.getByRole("row",{name:/Ops Watch/})).toHaveCount(0);
 await expect(table).toContainText("Нет проверенного снимка.");
});
