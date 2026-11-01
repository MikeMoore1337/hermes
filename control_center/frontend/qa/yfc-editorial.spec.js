import {test,expect} from "@playwright/test";

test.use({serviceWorkers:"block"});

const ID="a".repeat(32),SHA="b".repeat(64);
const row={article_id:ID,title:"Тестовая статья YFC",article_status:"draft",
 content_version:3,content_hash:SHA,source_count:2,claim_count:1,
 pending_claim_count:1,review_blockers:["claim_source_matrix_not_fully_verified"]};
const full={...row,description:"Описание материала",lead:"Вступление без сокращения",
 body_sections:[
  {heading:"Что изучали",paragraphs:["Первый полный абзац исследования","Второй полный абзац исследования"]},
  {heading:"Практические ограничения",paragraphs:["Третий полный абзац","Четвёртый полный абзац"]}
 ],
 claims:[{claim_id:"c1",claim_text:"Доказательства ограничены"}],
 sources:[{source_id:"s1",title:"Первичное исследование",url:"https://pmc.ncbi.nlm.nih.gov/articles/PMC00000001/",limitations:"Малая выборка"},
  {source_id:"s2",title:"Второе исследование",url:"https://pmc.ncbi.nlm.nih.gov/articles/PMC00000002/"}],
 claim_source_matrix:[{claim_id:"c1",source_ids:["s1","s2"],review_status:"pending",
  support_level:"partially_supports",limitations:"Требуется независимая научная проверка"}],
 risk_level:"moderate",evidence_level:"limited",domain_reviewer:null,
 provider:"local",model:"research-draft",review_blockers:["claim_source_matrix_not_fully_verified"]
};


const PROTOCOL="yfc-owner-editorial-bridge-v1";
function popupHtml({incomplete=false,invalidMatrix=false}={}){
 const detail=incomplete?{...full,body_sections:[]}:
  invalidMatrix?{...full,claim_source_matrix:[{...full.claim_source_matrix[0],source_ids:["unknown"]}]}:full;
 return `<!doctype html><html lang="ru"><meta charset="utf-8"><title>Root YFC</title>
 <body><h1>Подтвердить доступ YFC</h1>
 <button id="grant">Разрешить просмотр черновиков</button>
 <button id="publish" hidden>Подтверждаю публикацию в YFC</button>
 <script>
 const PROTOCOL=${JSON.stringify(PROTOCOL)};
 const LIST=${JSON.stringify([row])};
 const DETAIL=${JSON.stringify(detail)};
 let nonce=null,confirmed=false,pending=null;
 const send=(obj)=>window.opener.postMessage({protocol:PROTOCOL,nonce,...obj},"http://127.0.0.1:9133");
 window.addEventListener("message",e=>{
  if(e.source!==opener||e.origin!=="http://127.0.0.1:9133"||
     !e.data||e.data.protocol!==PROTOCOL)return;
  const m=e.data;
  if(m.kind==="hello"){nonce=m.nonce;return;}
  if(!confirmed||m.nonce!==nonce||m.kind!=="request")return;
  if(m.action==="publish"){
   pending=m;
   document.querySelector("#publish").hidden=false;
   return;
  }
  send({kind:"response",request_id:m.request_id,ok:true,
    data:m.action==="list"?LIST:DETAIL});
 });
 document.querySelector("#grant").onclick=()=>{
  confirmed=true;send({kind:"granted"});
 };
 document.querySelector("#publish").onclick=()=>{
  const m=pending;pending=null;
  document.querySelector("#publish").hidden=true;
  send({kind:"response",request_id:m.request_id,ok:true,
   data:{article_id:DETAIL.article_id,content_version:DETAIL.content_version,
    article_status:"published",
    canonical_url:"https://your-fitness-coach.ru/articles/test-article",
    editorial_decision:"root_owner_publication",scientific_verification:"not_attested"}});
 };
 send({kind:"ready"});
 <\/script></body></html>`;
}
async function prepare(page,options={}){
 const unexpected=[];
 await page.context().route("**/*",async route=>{
  const url=new URL(route.request().url());
  if(url.href==="https://app.your-fitness-coach.ru/admin/hermes-bridge")
   return route.fulfill({status:200,contentType:"text/html",body:popupHtml(options)});
  if(url.hostname!=="127.0.0.1"||url.port!=="9133"){
   unexpected.push(route.request().url());return route.abort("blockedbyclient");
  }
  if(url.pathname==="/"&&!url.search){
   const response=await route.fetch();
   return route.fulfill({response,body:(await response.text())
    .replace('data-auth-mode="proxy" data-authenticated="true"',
      'data-auth-mode="github" data-authenticated="true"')});
  }
  if(url.pathname.startsWith("/api/yfc/editorial/"))
   throw Error("Manual Root bearer transport must not be invoked");
  if(url.pathname==="/api/overview")
   return route.fulfill({status:503,contentType:"application/json",body:'{"error":"unavailable"}'});
  return route.continue();
 });
 return {unexpected};
}
async function connect(page){
 const popupEvent=page.waitForEvent("popup");
 await page.getByRole("button",{name:"Подтвердить доступ через YFC"}).click();
 const popup=await popupEvent;
 await popup.getByRole("button",{name:"Разрешить просмотр черновиков"}).click();
 await page.getByRole("button",{name:/Тестовая статья YFC/}).waitFor();
 return popup;
}
test("independent YFC Root window displays entire article and performs two owner confirmations",async({page})=>{
 const {unexpected}=await prepare(page);
 await page.setViewportSize({width:393,height:844});
 await page.goto("/");
 if((page.viewportSize()?.width||1280)<=980){
  await page.locator(".orbit-app-mobilebar").getByRole("button",{name:"Ещё"}).click();
  await page.locator(".atlas-section-nav").getByRole("button",{name:"Статьи YFC"}).click();
 }else{
  await page.locator(".atlas-section-nav").getByRole("button",{name:"Статьи YFC"}).click();
 }
 await expect(page.getByLabel("Временный токен YFC Root")).toHaveCount(0);
 await expect(page.getByRole("button",{name:/Проверил статью/})).toHaveCount(0);
 const popup=await connect(page);
 await page.getByRole("button",{name:/Тестовая статья YFC/}).click();
 for(const paragraph of ["Вступление без сокращения","Первый полный абзац исследования",
  "Второй полный абзац исследования","Третий полный абзац","Четвёртый полный абзац"])
  await expect(page.getByText(paragraph,{exact:true})).toBeVisible();
 await expect(page.getByRole("link",{name:/Первичное исследование/})).toBeVisible();
 await expect(page.getByRole("link",{name:/Второе исследование/})).toBeVisible();
 await expect(page.getByText(/Источники: Первичное исследование; Второе исследование/)).toBeVisible();
 await expect(page.getByText(/Ограничения: Требуется независимая научная проверка/)).toBeVisible();
 await expect(page.getByText(/undefined/)).toHaveCount(0);
 await page.getByRole("button",{name:"Режим чтения"}).click();
 await expect(page.getByText("Четвёртый полный абзац")).toBeVisible();
 await page.getByRole("button",{name:/Проверил статью/}).click();
 await expect(page.getByRole("dialog")).toContainText(SHA);
 await expect(page.getByRole("button",{name:"Опубликовать в YFC"})).toBeDisabled();
 await page.getByRole("checkbox").check();
 await page.getByRole("button",{name:"Опубликовать в YFC"}).click();
 await expect(popup.getByRole("button",{name:"Подтверждаю публикацию в YFC"})).toBeVisible();
 await expect(page.getByText("Публикация подтверждена YFC")).toHaveCount(0);
 await popup.getByRole("button",{name:"Подтверждаю публикацию в YFC"}).click();
 await expect(page.getByText("Публикация подтверждена YFC")).toBeVisible();
 expect(unexpected).toEqual([]);
 const viewport=await page.evaluate(()=>({innerWidth,scrollWidth:document.documentElement.scrollWidth}));
 expect(viewport.scrollWidth).toBeLessThanOrEqual(viewport.innerWidth+1);
});
test("invalid full-text never offers publication",async({page})=>{
 const {unexpected}=await prepare(page,{incomplete:true});
 await page.goto("/");
 if((page.viewportSize()?.width||1280)<=980){
  await page.locator(".orbit-app-mobilebar").getByRole("button",{name:"Ещё"}).click();
  await page.locator(".atlas-section-nav").getByRole("button",{name:"Статьи YFC"}).click();
 }else{
  await page.locator(".atlas-section-nav").getByRole("button",{name:"Статьи YFC"}).click();
 }
 await connect(page);
 await page.getByRole("button",{name:/Тестовая статья YFC/}).click();
 await expect(page.getByText(/Черновик не подтверждён/)).toBeVisible();
 await expect(page.getByRole("button",{name:/Проверил статью/})).toHaveCount(0);
 expect(unexpected).toEqual([]);
});

test("missing foreign source_ids fail closed without owner publish controls",async({page})=>{
 const {unexpected}=await prepare(page,{invalidMatrix:true});
 await page.goto("/");
 if((page.viewportSize()?.width||1280)<=980){
  await page.locator(".orbit-app-mobilebar").getByRole("button",{name:"Ещё"}).click();
  await page.locator(".atlas-section-nav").getByRole("button",{name:"Статьи YFC"}).click();
 }else{
  await page.locator(".atlas-section-nav").getByRole("button",{name:"Статьи YFC"}).click();
 }
 await connect(page);
 await page.getByRole("button",{name:/Тестовая статья YFC/}).click();
 await expect(page.getByText(/Черновик не подтверждён/)).toBeVisible();
 await expect(page.getByRole("button",{name:/Проверил статью/})).toHaveCount(0);
 await expect(page.getByRole("button",{name:"Опубликовать в YFC"})).toHaveCount(0);
 expect(unexpected).toEqual([]);
});
