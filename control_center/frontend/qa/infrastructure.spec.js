import {test,expect} from "@playwright/test";
import {mkdirSync} from "node:fs";
import {resolve} from "node:path";

const evidence=resolve("../../docs/ux/evidence/h15-infrastructure");
const overview={schema:1,mode:"read_only",services:[],generated_at:new Date().toISOString()};
const host=(name,cpu,ram,disk)=>({
 host:name,name:"VPS "+(name==="hermes"?"Hermes":"YFC"),
 status:"online",observed_at:new Date().toISOString(),
 metrics:{cpu_used_percent:cpu,ram_used_percent:ram,ram_total_bytes:1000000000,
  ram_used_bytes:ram*10000000,swap_total_bytes:500000000,swap_used_bytes:50000000,
  disk_used_percent:disk,disk_total_bytes:2000000000,disk_used_bytes:disk*20000000,
  uptime_seconds:7200,load1:0.11,load5:0.22,load15:0.33,
  cpu_cores:4,inode_used_percent:19,
  network_rates:{eth0:{rx_bytes_per_second:1200000,tx_bytes_per_second:2200000}}}
});
async function setup(page,mode="online"){
 await page.route("**/api/overview",route=>route.fulfill({status:200,
  contentType:"application/json",body:JSON.stringify({...overview,generated_at:new Date().toISOString()})}));
 await page.route("**/api/infrastructure/hosts",route=>route.fulfill({status:200,
  contentType:"application/json",body:JSON.stringify({schema:1,mode:"read_only",hosts:
   mode==="online"?[host("hermes",23,40,52),host("yfc",77,65,83)]:
   [host("hermes",23,40,52),{host:"yfc",name:"VPS YFC",status:"not_connected"}]})}));
 await page.route("**/api/infrastructure/history?*",route=>{
  const u=new URL(route.request().url());
  const cpu=u.searchParams.get("host")==="hermes"?23:77;
  const records=[1,2].map(i=>({observed_at:new Date(Date.now()-i*60000).toISOString(),
   cpu,ram:cpu===23?40:65,disk:cpu===23?52:83}));
  return route.fulfill({status:200,contentType:"application/json",body:JSON.stringify({
   schema:1,host:u.searchParams.get("host"),samples:records})});
 });
}
for(const width of [320,393,1440]){
 test("Independent infrastructure cards, history and mobile visual "+width,async({page})=>{
  await page.setViewportSize({width,height:900});
  await setup(page);
  await page.goto("/");
  await page.getByRole("button",{name:"Инфраструктура"}).click();
  const panel=page.getByRole("region",{name:"Мониторинг VPS Hermes и YFC"});
  await expect(panel).toBeVisible();
  const hermes=panel.locator(".infra294-card").nth(0);
  const yfc=panel.locator(".infra294-card").nth(1);
  await expect(hermes.getByRole("heading",{name:"VPS Hermes"})).toBeVisible();
  await expect(yfc.getByRole("heading",{name:"VPS YFC"})).toBeVisible();
  await expect(hermes.getByText("23%",{exact:true})).toBeVisible();
  await expect(yfc.getByText("77%",{exact:true})).toBeVisible();
  await expect(hermes.getByText("Сеть eth0:",{exact:false})).toBeVisible();
  await expect(yfc.getByText("Inode /",{exact:true})).toBeVisible();
  await hermes.locator("summary").click();
  await expect(hermes.locator(".infra294-chart")).toContainText("CPU");
  await expect(hermes.locator(".infra294-chart polyline")).toHaveAttribute("points",/\d/);
  await yfc.locator("summary").click();
  await expect(yfc.locator(".infra294-chart polyline")).toHaveAttribute("points",/\d/);
  const hermesPoints=await hermes.locator(".infra294-chart polyline").getAttribute("points");
  const yfcPoints=await yfc.locator(".infra294-chart polyline").getAttribute("points");
  expect(hermesPoints).not.toBe(yfcPoints);
  for(const points of [hermesPoints,yfcPoints]){
   const xs=points.trim().split(/\s+/).map(coord=>Number(coord.split(",")[0]));
   expect(xs.length).toBeGreaterThanOrEqual(2);
   expect(xs[0],"Chart must not collapse when data is reversed").toBeLessThan(xs[xs.length-1]);
  }
  const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1);
  expect(overflow).toBe(false);
  mkdirSync(evidence,{recursive:true});
  await page.screenshot({path:resolve(evidence,"infrastructure-"+width+".png"),fullPage:true});
  await page.locator(".atlas-section-nav").getByRole("button",{name:"Обзор"}).click();
  await expect(panel).toBeHidden();
 });
}
test("Unconnected YFC never displays a fabricated zero",async({page})=>{
 await setup(page,"partial");
 await page.goto("/");
 await page.getByRole("button",{name:"Инфраструктура"}).click();
 const panel=page.getByRole("region",{name:"Мониторинг VPS Hermes и YFC"});
 const yfc=panel.locator(".infra294-card").nth(1);
 await expect(yfc.getByText("Не подключён")).toBeVisible();
 await expect(yfc.getByText(/Цифры не подставляются/)).toBeVisible();
 await expect(yfc.locator("[role=progressbar]")).toHaveCount(0);
 await expect(panel.locator(".infra294-card")).toHaveCount(2);
});
