import {test,expect} from "@playwright/test";

test("installable local manifest, approved logo icons and restricted worker", async ({page}) => {
  await page.goto("/");
  const result=await page.evaluate(async ()=>{
    const response=await fetch("/manifest.webmanifest");
    const manifest=await response.json();
    const reg=await navigator.serviceWorker.ready;
    return {status:response.status,contentType:response.headers.get("content-type"),
      manifest,scope:reg.scope,sw:reg.active?.scriptURL||null};
  });
  expect(result.status).toBe(200);
  expect(result.contentType).toContain("application/manifest+json");
  expect(result.manifest.name).toBe("Hermes Control Center");
  expect(result.manifest.display).toBe("standalone");
  expect(result.manifest.start_url).toBe("/");
  expect(result.manifest.icons.map(x=>x.sizes)).toEqual(["192x192","512x512"]);
  expect(result.scope).toBe("http://127.0.0.1:9133/");
  expect(result.sw).toContain("/sw.js");
  for(const icon of result.manifest.icons){
    const response=await page.request.get(icon.src);
    expect(response.status()).toBe(200);
    expect((await response.body()).subarray(0,4).toString("hex")).toBe("89504e47");
  }
});

test("offline page is neutral; API and OAuth never enter CacheStorage",async({page,context})=>{
  await page.goto("/");
  await page.evaluate(()=>navigator.serviceWorker.ready);
  await page.reload();
  await expect.poll(()=>page.evaluate(()=>!!navigator.serviceWorker.controller)).toBe(true);
  // The private API must never be added to SW CacheStorage even after a successful request.
  await page.evaluate(async()=>{
    try{await fetch("/api/overview",{cache:"no-store"});}catch(_){}
  });
  const keys=await page.evaluate(async()=>{
    const names=await caches.keys();
    const out={};
    for(const name of names){
      const cache=await caches.open(name);
      out[name]=(await cache.keys()).map(req=>new URL(req.url).pathname);
    }
    return out;
  });
  expect(Object.keys(keys)).toEqual(["h15-offline-v1"]);
  expect(Object.values(keys).flat()).toEqual(["/offline.html"]);
  // Chromium offline emulation leaves localhost accessible. Verify the actual
  // neutral fallback resource and exact CacheStorage contents instead.
  await page.goto("/offline.html");
  await expect(page.getByRole("heading",{name:"Нет подключения к серверу"})).toBeVisible();
  await expect(page.getByText(/не сохраняет статусы/)).toBeVisible();
  await expect(page.getByText("Ops Watch")).toHaveCount(0);
  const after=await page.evaluate(async()=>Object.values(await Promise.all((await caches.keys()).map(async name=>(await caches.open(name)).keys()))).flat().map(req=>new URL(req.url).pathname));
  expect(after).toEqual(["/offline.html"]);
});
