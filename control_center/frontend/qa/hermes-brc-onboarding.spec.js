import {test,expect} from "@playwright/test";

test.use({serviceWorkers:"block"});
const preview={schema:1,status:"preview_only",repository:"https://github.com/example/project.git",
 device:"Windows sandbox",root:"/workspace/projects/project",scope:"sandbox",catalog:"not_reserved",
 remote:"not_checked",filesystem:"not_checked",can_connect:false};

async function setup(page,reply=preview,status=200){
 await page.route("**/api/providers/hermes-brc",route=>route.fulfill({status:503,body:"{}"}));
 await page.route("**/api/providers/hermes-brc/onboarding-preview",async route=>{
  expect(route.request().method()).toBe("POST");
  expect(route.request().postDataJSON()).toEqual({repository_url:"https://github.com/example/project"});
  await route.fulfill({status,contentType:"application/json",body:JSON.stringify(reply)});
 });
 await page.goto("/hermes-brc");
 await page.getByRole("button",{name:"Подключить проект"}).click();
}

for(const width of [320,393,768,1440]){
 test("sandbox preview is honest and responsive "+width,async({page},testInfo)=>{
  await page.setViewportSize({width,height:width<400?844:900});
  await page.emulateMedia({reducedMotion:"reduce"});
  await setup(page);
  const dialog=page.getByRole("dialog"), input=page.getByLabel("Ссылка на репозиторий");
  await expect(dialog).toBeVisible();await expect(input).toBeFocused();
  await input.fill("https://github.com/example/project");
  await page.getByRole("button",{name:"Проверить",exact:true}).click();
  await expect(dialog.getByRole("heading",{name:"Проверьте подключение"})).toBeFocused();
  await expect(dialog).toContainText("/workspace/projects/project");
  await expect(dialog).toContainText("не проверены");
  await expect(dialog.getByRole("button",{name:"Подключить",exact:true})).toBeDisabled();
  const dimensions=await page.evaluate(()=>{const d=document.querySelector("#brc-onboard");
   return {viewport:innerWidth,page:document.documentElement.scrollWidth,dialog:d.clientWidth,content:d.scrollWidth};});
  expect(dimensions.page).toBeLessThanOrEqual(dimensions.viewport+1);
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.dialog+1);
  const screenshot=testInfo.outputPath("h454-onboarding-preview-"+width+".png");
  await page.screenshot({path:screenshot,fullPage:true,animations:"disabled"});
  await testInfo.attach("h454-onboarding-preview-"+width+".png",{path:screenshot,contentType:"image/png"});
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(page.getByRole("button",{name:"Подключить проект"})).toBeFocused();
 });
}

test("reserved catalog name cannot be connected",async({page})=>{
 await setup(page,{...preview,catalog:"reserved"});
 await page.getByLabel("Ссылка на репозиторий").fill("https://github.com/example/project");
 await page.getByRole("button",{name:"Проверить",exact:true}).click();
 const dialog=page.getByRole("dialog");
 await expect(dialog).toContainText("имя уже есть во встроенном каталоге");
 await expect(dialog.getByRole("button",{name:"Подключить",exact:true})).toBeDisabled();
});

test("keyboard navigation stays in the dialog",async({page})=>{
 await setup(page);
 const dialog=page.getByRole("dialog");
 for(let i=0;i<4;i++){
  await page.keyboard.press("Tab");
  await expect(dialog.locator(":focus")).toHaveCount(1);
 }
 for(let i=0;i<4;i++){
  await page.keyboard.press("Shift+Tab");
  await expect(dialog.locator(":focus")).toHaveCount(1);
 }
});

test("forced colors retain an operable focused input",async({page})=>{
 await page.emulateMedia({forcedColors:"active"});
 await setup(page);
 const input=page.getByLabel("Ссылка на репозиторий");
 await expect(input).toBeFocused();
 expect(await input.evaluate(element=>getComputedStyle(element).outlineStyle)).not.toBe("none");
});

test("closing an in-flight preview cannot update a reopened dialog",async({page})=>{
 let release,arrived;
 const started=new Promise(resolve=>{arrived=resolve;});
 const gate=new Promise(resolve=>{release=resolve;});
 await page.route("**/api/providers/hermes-brc",route=>route.fulfill({status:503,body:"{}"}));
 await page.route("**/api/providers/hermes-brc/onboarding-preview",async route=>{
  arrived();await gate;
  try{await route.fulfill({status:200,contentType:"application/json",body:JSON.stringify(preview)});}catch{}
 });
 await page.goto("/hermes-brc");await page.getByRole("button",{name:"Подключить проект"}).click();
 await page.getByLabel("Ссылка на репозиторий").fill("https://github.com/example/project");
 await page.getByRole("button",{name:"Проверить",exact:true}).click();await started;
 await page.keyboard.press("Escape");
 await page.getByRole("button",{name:"Подключить проект"}).click();
 release();
 await expect(page.getByRole("dialog")).toContainText("Шаг 1 из 2");
 await expect(page.getByLabel("Ссылка на репозиторий")).toHaveValue("");
 await expect(page.getByRole("heading",{name:"Проверьте подключение"})).not.toBeVisible();
});

test("invalid input never reaches preview endpoint",async({page})=>{
 let calls=0;
 await page.route("**/api/providers/hermes-brc",route=>route.fulfill({status:503,body:"{}"}));
 await page.route("**/api/providers/hermes-brc/onboarding-preview",route=>{calls++;return route.abort();});
 await page.goto("/hermes-brc");await page.getByRole("button",{name:"Подключить проект"}).click();
 await page.getByLabel("Ссылка на репозиторий").fill("https://github.com/example/project?token=secret");
 await page.getByRole("button",{name:"Проверить",exact:true}).click();
 await expect(page.getByRole("dialog")).toContainText("Введите HTTPS-ссылку GitHub");
 await expect(page.getByLabel("Ссылка на репозиторий")).toHaveAttribute("aria-invalid","true");
 expect(calls).toBe(0);
});

for(const [description,reply,status] of [
 ["unavailable",{},503], ["forged capability",{...preview,can_connect:true},200],
 ["forged target",{...preview,root:"/host-private"},200],
]){
 test("refuses "+description,async({page})=>{
  await setup(page,reply,status);
  await page.getByLabel("Ссылка на репозиторий").fill("https://github.com/example/project");
  await page.getByRole("button",{name:"Проверить",exact:true}).click();
  await expect(page.getByRole("dialog")).toContainText("Предпросмотр недоступен");
  await expect(page.getByRole("button",{name:"Подключить",exact:true})).not.toBeVisible();
 });
}
