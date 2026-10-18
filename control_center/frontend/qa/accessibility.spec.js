import {test,expect} from "@playwright/test";

// #179: deterministic accessibility contracts, intentionally no production API,
// private data, network font, CDN, axe CDN, or OAuth exchange.
test.use({serviceWorkers:"block"});

const services=[
 {id:"ops",name:"Ops Watch",unit:"hermes-ops-watch.timer",state:"active",kind:"schedule"},
 {id:"qa",name:"QA Advisor",unit:"hermes-qa-watch.timer",state:"failed",kind:"schedule"},
 {id:"agent",name:"Полный AI Agent (без допуска)",unit:"hermes-agent-sandbox.service",state:"blocked",kind:"restricted"}
];

async function fixture(page,overrides={}){
 await page.route("**/api/overview",route=>route.fulfill({
  status:200,contentType:"application/json",
  body:JSON.stringify({
   schema:1,mode:"read_only",generated_at:new Date().toISOString(),
   services,agent_policy:"Ограниченный H-01. Полный AI Agent не допущен.",
   ...overrides
  })
 }));
}

async function publicGithubLogin(page){
 await page.route("http://127.0.0.1:9133/",async route=>{
  const response=await route.fetch();
  let html=(await response.text()).replace(
   ' data-auth-mode="proxy" data-authenticated="true"',
   ' data-auth-mode="github" data-authenticated="false"'
  );
  for(const widget of ["desktop-commander","ai-analytics","infrastructure","provider-quota"]){
   html=html.replace(`<link rel="stylesheet" href="/${widget}.css">`,"");
   html=html.replace(`<script src="/${widget}.js" defer></script>`,"");
  }
  await route.fulfill({response,body:html});
 });
}

test("public GitHub login is accessible by Tab without protected data",async({page})=>{
 let overviewCalls=0;
 await publicGithubLogin(page);
 await page.route("**/api/overview",route=>{overviewCalls++;return route.abort();});
 await page.goto("/");
 await expect(page.locator("html")).toHaveAttribute("lang","ru");
 await expect(page.getByRole("main")).toHaveCount(1);
 await expect(page.getByRole("heading",{level:1})).toHaveCount(1);
 const login=page.getByRole("link",{name:"Войти через GitHub"});
 await expect(login).toHaveAttribute("href","/auth/github/start");
 await page.keyboard.press("Tab");
 await expect(login).toBeFocused();
 const outline=await login.evaluate(el=>getComputedStyle(el).outlineStyle);
 expect(outline,"Keyboard focus has a visible outline").not.toBe("none");
 await expect(page.getByRole("button",{name:"Устройства"})).toHaveCount(0);
 await expect(page.getByRole("table")).toHaveCount(0);
 expect(overviewCalls).toBe(0);
});

test("operator landmarks, labelled controls, keyboard view switching and no colour-only status",async({page})=>{
 await fixture(page);
 await page.goto("/");
 await expect(page.getByRole("main")).toHaveCount(1);
 await expect(page.getByRole("heading",{level:1})).toHaveCount(1);
 await expect(page.getByRole("navigation",{name:"Разделы управления"})).toHaveCount(1);
 await expect(page.getByRole("textbox",{name:"Поиск по службам"})).toBeVisible();
 await expect(page.getByRole("combobox",{name:"Фильтр по состоянию"})).toBeVisible();
 await expect(page.getByRole("row",{name:/QA Advisor.*Сбой/})).toBeVisible();
 await expect(page.getByRole("row",{name:/Полный AI Agent.*Не допущен/})).toBeVisible();
 const qa=page.locator(".atlas-section-nav").getByRole("button",{name:"QA и CI"});
 await qa.focus();
 await qa.press("Space");
 await expect(qa).toHaveAttribute("aria-current","page");
 await expect(page.getByRole("row",{name:/QA Advisor/})).toBeVisible();
 await expect(page.getByRole("row",{name:/Ops Watch/})).toHaveCount(0);
 const filter=page.getByRole("combobox",{name:"Фильтр по состоянию"});
 await filter.selectOption("active");
 await expect(page.getByText("По текущим условиям служб не найдено.")).toBeVisible();
 await filter.selectOption("all");
 await expect(page.getByRole("row",{name:/QA Advisor/})).toBeVisible();
});

test("stale snapshot exposes an alert and never reports a healthy unit",async({page})=>{
 await fixture(page,{generated_at:"2020-01-01T00:00:00Z"});
 await page.goto("/");
 await expect(page.getByRole("alert")).toContainText(/устаревш/);
 await expect(page.getByRole("row",{name:/Ops Watch/})).toHaveCount(0);
 await expect(page.getByText("Нет проверенного снимка.")).toBeVisible();
});

test("API unavailability is explicit and no protected state is simulated",async({page})=>{
 await page.route("**/api/overview",route=>route.fulfill({status:503,body:"unavailable"}));
 await page.goto("/");
 await expect(page.getByRole("alert")).toContainText(/503/);
 await expect(page.getByRole("row",{name:/Ops Watch/})).toHaveCount(0);
});

test("reduced motion disables the busy spinner without hiding the control",async({page})=>{
 await page.emulateMedia({reducedMotion:"reduce"});
 await fixture(page);await page.goto("/");
 const refresh=page.locator(".atlas-section-nav .refresh-button");
 await expect(refresh).toBeVisible();
 const animation=await refresh.locator("svg").evaluate(svg=>{
  svg.classList.add("spin");
  return getComputedStyle(svg).animationName;
 });
 expect(animation).toBe("none");
});

for(const width of [320,393,1440]){
 test(`accessible controls remain usable at ${width}px`,async({page})=>{
  await page.setViewportSize({width,height:844});
  await fixture(page);await page.goto("/");
  const overview=page.locator(".atlas-section-nav").getByRole("button",{name:"Обзор"});
  await expect(overview).toBeVisible();
  const search=page.getByRole("textbox",{name:"Поиск по службам"});
  await search.focus();await search.fill("Ops");
  await expect(page.getByRole("row",{name:/Ops Watch/})).toBeVisible();
  const size=await page.evaluate(()=>({viewport:innerWidth,root:document.documentElement.scrollWidth}));
  expect(size.root,"Whole-document horizontal overflow").toBeLessThanOrEqual(size.viewport+1);
 });
}
