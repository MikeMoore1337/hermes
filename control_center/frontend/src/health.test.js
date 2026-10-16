import test from "node:test";
import assert from "node:assert/strict";
import {validSnapshot,counts,filterServices} from "./health.js";
const now=Date.parse("2026-10-16T15:00:00Z");
const services=[
{id:"ops",name:"Ops Watch",unit:"hermes-ops-watch.timer",state:"active",kind:"schedule"},
{id:"qa",name:"QA Advisor",unit:"hermes-qa-watch.timer",state:"failed",kind:"schedule"},
{id:"agent",name:"Постоянный AI Agent",unit:"hermes-agent-sandbox.service",state:"blocked",kind:"restricted"}];
const snap={schema:1,mode:"read_only",generated_at:new Date(now).toISOString(),services};
test("schema, freshness and identity validation",()=>{
 assert.equal(validSnapshot(snap,now),true);
 assert.equal(validSnapshot({...snap,schema:3},now),false);
 assert.equal(validSnapshot({...snap,mode:"write"},now),false);
 assert.equal(validSnapshot({...snap,generated_at:"2025-01-01T00:00:00Z"},now),false);
 assert.equal(validSnapshot({...snap,services:[{id:"ops",name:"x",state:"active"}]},now),false);
});
test("operational count excludes deliberate NO-GO from attention",()=>{
 assert.deepEqual(counts(services),{active:1,attention:1,blocked:1,total:3});
});
test("navigation groups, search and status filter are composable",()=>{
 assert.equal(filterServices(services,"all","","all").length,3);
 assert.equal(filterServices(services,"ops","","all").length,1);
 assert.equal(filterServices(services,"qa","","failed").length,1);
 assert.equal(filterServices(services,"all","Advisor","all").length,1);
 assert.equal(filterServices(services,"agent","","blocked")[0].id,"agent");
});
