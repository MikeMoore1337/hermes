// #455: exercise REAL pinned TypeScript observer module after upstream pnpm build.
// No /state mount, no production access, no tokens, no network listeners.
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
if (process.argv.length !== 3 || !process.argv[2].endsWith('/packages/relay/dist/hermes-brc-observer.js')) {
  throw Error('BRC_OBSERVER_COMPILED_SOURCE_REQUIRED');
}
const { sanitizedLiveObservation, observerEnabled } = await import(pathToFileURL(process.argv[2]).href);

const now = 1792872000000;
const names = ['H15 Windows permanent sandbox', 'H15 Hermes VPS sandbox', 'H15 YFC VPS sandbox'];
const id = ['h15-win-05be75515428','h15-hermes-ab005bc0e0ea','h15-yfc-c6ee0d53e858'];
const mkRow = (name, i) => ({
  device_id:id[i], user_id:'owner', name, platform:'linux/docker',
  paused:0, last_seen:now-1000, token_hash:'SENSITIVE_DO_NOT_EXPORT',
});
let rows = names.map(mkRow);
let connected = rows.map((r,i)=>({deviceId:r.device_id,name:r.name,
  platform:'linux',lastSeen:now-1000,hostname:'private',agentVersion:'test'}));
const store = {listDevices(u){return u === 'owner'?rows:[]}};
const hub = {list(u){return u === 'owner'?connected:[]}};
const good = sanitizedLiveObservation(hub,store,'owner',now);
// Regression from actual owner production incident: SQLite stores the
// deployed sandbox class linux/docker, but brc-agent hello uses Node's
// process.platform = linux. The live projection MUST refresh in this state.
assert.equal(rows[0].platform,'linux/docker');
assert.equal(connected[0].platform,'linux');
const next = sanitizedLiveObservation(hub,store,'owner',now+30000);
assert.equal(next.status,'online');
assert.equal(next.devices[0].last_seen_age_seconds,31);
assert.equal(good.status,'online');
assert.deepEqual(good.devices.map(d=>d.name),names);
assert.equal(good.workspaces.length,4);
assert.deepEqual(good.workspaces.map(x=>x.state),Array(4).fill('reachable_not_git_verified'));
assert.equal(good.execution_verified,false);
assert.equal(good.native_host_access,false);
assert.equal(good.onboarding_enabled,false);
assert(!JSON.stringify(good).includes('SENSITIVE_DO_NOT_EXPORT'));
assert(!JSON.stringify(good).includes(id[0]));
assert(!JSON.stringify(good).includes('owner'));
const native = {device_id:'h454-win-01335a1f6e6705b4',user_id:'owner',
  name:'H15 Windows native read-only',platform:'win32',paused:1,last_seen:now-25000,
  token_hash:'SENSITIVE_NATIVE'};
rows = [...rows,native];
const paused = sanitizedLiveObservation(hub,store,'owner',now);
assert.deepEqual(paused.devices, good.devices);
assert(!JSON.stringify(paused).includes('SENSITIVE_NATIVE'));
connected = connected.slice(1);
const offline = sanitizedLiveObservation(hub,store,'owner',now);
assert.equal(offline.status,'partial');
assert.equal(offline.devices[0].status,'offline');
assert(offline.workspaces.every(x=>x.state==='not_ready'));
connected = [];
const down = sanitizedLiveObservation(hub,store,'owner',now);
assert.equal(down.status,'unavailable');
const fails = [
  () => {rows = [...rows,{...native,device_id:'evil-native'}];},
  () => {rows = [mkRow('H15 Windows permanent sandbox',0),mkRow('H15 Windows permanent sandbox',1),mkRow(names[2],2)];},
  () => {rows = [mkRow(names[0],0),mkRow(names[1],1),{...mkRow(names[2],2),platform:'win32'}];},
  () => {rows = rows.slice(0,2);},
];
for(const mutate of fails){
  rows = names.map(mkRow); mutate();
  assert.throws(()=>sanitizedLiveObservation(hub,store,'owner',now));
}
// Deliberately reject forged hello claims, wrong labels and other OS
// types. Only the genuine platform=linux is accepted for these devices.
connected = names.map((name,i)=>({deviceId:id[i],name,platform:'linux',lastSeen:now-1000}));
for(const wrongPlatform of ['win32','darwin','linux/docker','freebsd','']) {
  connected = [ {...connected[0], platform:wrongPlatform} ];
  rows = names.map(mkRow);
  assert.throws(()=>sanitizedLiveObservation(hub,store,'owner',now), /forged_hello/);
}
connected = [{...connected[0],name:'FORGED NAME',platform:'linux'}];
assert.throws(()=>sanitizedLiveObservation(hub,store,'owner',now), /forged_hello/);
connected = names.map((name,i)=>({deviceId:id[i],name,platform:'linux',lastSeen:now-1000}));
rows = names.map(mkRow);
rows[0] = {...rows[0],platform:'linux'};
assert.throws(()=>sanitizedLiveObservation(hub,store,'owner',now), /unapproved_device/);
assert.equal(observerEnabled('/tmp/untrusted-marker'),false);
console.log('H455_PINNED_LIVE_OBSERVER_PROJECTION=PASS');
