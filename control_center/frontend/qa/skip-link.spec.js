import {test,expect} from "@playwright/test";
import {mkdirSync} from "node:fs";
import {resolve} from "node:path";

test.use({serviceWorkers:"block"});
const evidence=resolve("../../docs/ux/evidence/h15-skip-link");
mkdirSync(evidence,{recursive:true});

async function fixture(page){
 await page.route("**/api/overview",route=>route.fulfill({status:200,contentType:"application/json",
  body:JSON.stringify({schema:1,mode:"read_only",generated_at:new Date().toISOString(),
   services:[{id:"ops",name:"Ops Watch",unit:"hermes-ops-watch.timer",state:"active",kind:"schedule"}]})
 }));
}

for(const width of [320,393,1440]){
 test(`focus-visible skip link is first and moves keyboard focus to main at ${width}px`,async({page})=>{
  await page.setViewportSize({width,height:850});
  await fixture(page);
  await page.goto("/");
  const link=page.getByRole("link",{name:"Перейти к основному содержимому"});
  const main=page.getByRole("main");
  await expect(main).toHaveAttribute("id","main-content");
  await expect(main).toHaveAttribute("tabindex","-1");
  const hidden=await link.boundingBox();
  expect(hidden).not.toBeNull();
  expect(hidden.y+hidden.height,"Link should be offscreen before focus").toBeLessThan(0);
  await page.screenshot({path:resolve(evidence,`before-${width}.png`),fullPage:true});
  await page.keyboard.press("Tab");
  await expect(link).toBeFocused();
  const shown=await link.boundingBox();
  expect(shown.y,"Keyboard link must become visible").toBeGreaterThanOrEqual(0);
  expect(shown.x).toBeGreaterThanOrEqual(0);
  await page.screenshot({path:resolve(evidence,`after-focus-${width}.png`),fullPage:true});
  await link.press("Enter");
  await expect(main).toBeFocused();
  await expect(page).toHaveURL(/#main-content$/);
  const overflow=await page.evaluate(()=>document.documentElement.scrollWidth-innerWidth);
  expect(overflow,"No horizontal overflow at normal zoom").toBeLessThanOrEqual(1);
 });
}

test("public GitHub login is not preceded by a protected dashboard skip link",async({page})=>{
 await page.route("http://127.0.0.1:9133/",async route=>{
  const response=await route.fetch();
  const html=(await response.text()).replace(
   ' data-auth-mode="proxy" data-authenticated="true"',
   ' data-auth-mode="github" data-authenticated="false"'
  ).replace(/<script src="\/(desktop-commander|ai-analytics|infrastructure|provider-quota)\.js" defer><\/script>/g,"");
  await route.fulfill({response,body:html});
 });
 await page.goto("/");
 await expect(page.getByRole("link",{name:"Перейти к основному содержимому"})).toHaveCount(0);
 await expect(page.getByRole("link",{name:"Войти через GitHub"})).toHaveCount(1);
});
