import {test,expect} from "@playwright/test";

test.use({serviceWorkers:"block"});

const ID="a".repeat(32),SHA="b".repeat(64);
const row={article_id:ID,title:"Тестовая статья YFC",article_status:"draft",
 content_version:3,content_hash:SHA,source_count:1,claim_count:1,
 pending_claim_count:1,review_blockers:["claim_source_matrix_not_fully_verified"]};
const full={...row,description:"Описание материала",lead:"Вступление без сокращения",
 body_sections:[
  {heading:"Что изучали",paragraphs:["Первый полный абзац исследования","Второй полный абзац исследования"]},
  {heading:"Практические ограничения",paragraphs:["Третий полный абзац","Четвёртый полный абзац"]}
 ],
 claims:[{claim_id:"c1",claim_text:"Доказательства ограничены"}],
 sources:[{source_id:"s1",title:"Первичное исследование",url:"https://pmc.ncbi.nlm.nih.gov/articles/PMC00000001/",limitations:"Малая выборка"}],
 claim_source_matrix:[{claim_id:"c1",source_id:"s1",review_status:"pending",support_level:"partially_supports"}],
 risk_level:"moderate",evidence_level:"limited",domain_reviewer:null,
 provider:"local",model:"research-draft",review_blockers:["claim_source_matrix_not_fully_verified"]
};

async function prepare(page,{incomplete=false}={}){
 const outbound=[],unexpected=[];
 await page.route("**/*",async route=>{
  const url=new URL(route.request().url());
  if(url.hostname!=="127.0.0.1"||url.port!=="9133"){
   unexpected.push(route.request().url());return route.abort("blockedbyclient");
  }
  if(url.pathname==="/"&&!url.search){
   const response=await route.fetch();
   return route.fulfill({response,body:(await response.text())
    .replace('data-auth-mode="proxy" data-authenticated="true"',
      'data-auth-mode="github" data-authenticated="true"')});
  }
  if(url.pathname.startsWith("/api/yfc/editorial/")){
   const body=route.request().postDataJSON();
   outbound.push({action:url.pathname.split("/").pop(),body});
   let result=[],status=200;
   if(url.pathname.endsWith("/list"))result=[row];
   else if(url.pathname.endsWith("/detail")){
    result=incomplete?{...full,body_sections:[]}:full;
   }else if(url.pathname.endsWith("/publish")){
    result={article_id:ID,content_version:3,article_status:"published",
      canonical_url:"https://your-fitness-coach.ru/articles/test-article",
      editorial_decision:"root_owner_publication",scientific_verification:"not_attested"};
   }else status=404;
   return route.fulfill({status,contentType:"application/json",body:JSON.stringify(result)});
  }
  if(url.pathname==="/api/overview"){
   return route.fulfill({status:503,contentType:"application/json",body:'{"error":"snapshot_unavailable"}'});
  }
  if(url.pathname.startsWith("/api/")){
   return route.fulfill({status:503,contentType:"application/json",body:'{"error":"unavailable"}'});
  }
  return route.continue();
 });
 return {outbound,unexpected};
}

test("owner reads every full paragraph and explicitly publishes one exact YFC draft",async({page})=>{
 const {outbound,unexpected}=await prepare(page);
 await page.setViewportSize({width:393,height:844});
 await page.goto("/");
 await page.getByRole("button",{name:"Статьи YFC"}).first().click();
 await expect(page.getByRole("heading",{name:"Статьи YFC"})).toBeVisible();
 await expect(page.getByRole("button",{name:/Проверил статью/})).toHaveCount(0);
 await page.getByLabel("Временный токен YFC Root").fill("synthetic_only_browser_token_do_not_log_123456");
 await page.getByRole("button",{name:"Загрузить черновики"}).click();
 await page.getByRole("button",{name:/Тестовая статья YFC/}).click();
 for(const paragraph of ["Вступление без сокращения","Первый полный абзац исследования",
  "Второй полный абзац исследования","Третий полный абзац","Четвёртый полный абзац"]){
  await expect(page.getByText(paragraph,{exact:true})).toBeVisible();
 }
 await expect(page.getByText("Первичное исследование")).toBeVisible();
 await expect(page.getByText(/claim_source_matrix_not_fully_verified/)).toBeVisible();
 await page.getByRole("button",{name:"Режим чтения"}).click();
 await expect(page.getByRole("button",{name:"Вернуть очередь"})).toBeVisible();
 await expect(page.getByText("Четвёртый полный абзац")).toBeVisible();
 await page.getByRole("button",{name:/Проверил статью/}).click();
 await expect(page.getByRole("dialog")).toContainText(SHA);
 await expect(page.getByRole("button",{name:"Опубликовать в YFC"})).toBeDisabled();
 await page.getByRole("checkbox").check();
 await page.getByRole("button",{name:"Опубликовать в YFC"}).click();
 await expect(page.getByText("Публикация подтверждена YFC")).toBeVisible();
 const publishes=outbound.filter(x=>x.action==="publish");
 expect(publishes).toHaveLength(1);
 expect(publishes[0].body).toMatchObject({
  article_id:ID,content_hash:SHA,content_version:3,owner_confirmed:true
 });
 expect(unexpected).toEqual([]);
 const viewport=await page.evaluate(()=>({innerWidth,scrollWidth:document.documentElement.scrollWidth}));
 expect(viewport.scrollWidth).toBeLessThanOrEqual(viewport.innerWidth+1);
});

test("incomplete article never exposes a publication button",async({page})=>{
 const {outbound,unexpected}=await prepare(page,{incomplete:true});
 await page.goto("/");
 await page.getByRole("button",{name:"Статьи YFC"}).first().click();
 await page.getByLabel("Временный токен YFC Root").fill("synthetic_only_browser_token_do_not_log_123456");
 await page.getByRole("button",{name:"Загрузить черновики"}).click();
 await page.getByRole("button",{name:/Тестовая статья YFC/}).click();
 await expect(page.getByText(/Черновик не подтверждён/)).toBeVisible();
 expect(outbound.filter(x=>x.action==="publish")).toHaveLength(0);
 expect(unexpected).toEqual([]);
});
