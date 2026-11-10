#!/usr/bin/env node
// H454: real pinned BRC HTTP native-device revocation status E2E, loopback only.
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {randomBytes} from 'node:crypto';

const {buildRelay}=await import(pathToFileURL(path.join(process.cwd(),
  'packages/relay/dist/app.js')).href);
const secret=()=>randomBytes(32).toString('hex');
const folder=mkdtempSync(path.join(tmpdir(),'h454-status-e2e-'));
const relay=buildRelay({
  port:0,host:'127.0.0.1',publicUrl:'http://127.0.0.1',
  trustProxy:false,dbFile:path.join(folder,'relay.sqlite'),
  sessionSecret:secret(),adminUser:'unit-only',adminPassword:secret(),
  relayVersion:'test-pinned',
},()=>{});
const profiles=[
 {name:'H454 Windows native read-only',platform:'win32',id:'h454-win-native-'+'a'.repeat(32)},
 {name:'H454 Hermes VPS native read-only',platform:'linux',id:'h454-linux-hermes-'+'b'.repeat(32)},
 {name:'H454 YFC VPS native read-only',platform:'linux',id:'h454-linux-yfc-'+'c'.repeat(32)},
];
async function inspect(port,token,extra=''){
  const r=await fetch('http://127.0.0.1:'+port+'/device/native-status'+extra,{
    headers:token ? {Authorization:'Bearer '+token}:{},
  });
  return {status:r.status,body:await r.json()};
}
try {
  await new Promise((resolve,reject)=>{
    relay.http.once('error',reject);relay.http.listen(0,'127.0.0.1',resolve);
  });
  const address=relay.http.address();
  if(!address||typeof address==='string')throw Error('HOSTED_PORT_ABSENT');
  const admin=relay.store.getUserByName('unit-only');
  if(!admin)throw Error('OWNER_NOT_CREATED');
  for(const x of profiles){
    const token=relay.store.issueDeviceToken(x.id,admin.id,x.name,x.platform);
    const active=await inspect(address.port,token);
    if(active.status!==200||active.body.schema!=='h454-native-device-status-v1'
       ||active.body.device_id!==x.id||active.body.active!==true
       ||active.body.owner_bound!==true
       ||Object.keys(active.body).sort().join(',')!=='active,device_id,owner_bound,schema')
      throw Error('ACTIVE_OWNER_BOUND_NATIVE_STATUS_MISSING');
    for(const extra of ['?device_id='+x.id,'?token='+encodeURIComponent(token)]){
      const response=await inspect(address.port,token,extra);
      if(response.status!==403)throw Error('QUERY_ARGUMENT_STATUS_BYPASS');
    }
    relay.store.setDevicePaused(x.id,true);
    const paused=await inspect(address.port,token);
    if(paused.status!==403)throw Error('PAUSED_NATIVE_REVOKED_NOT_DENIED');
    relay.store.setDevicePaused(x.id,false);
    const rotated=relay.store.issueDeviceToken(x.id,admin.id,x.name,x.platform);
    if((await inspect(address.port,token)).status!==403)
      throw Error('OLD_NATIVE_BEARER_VALID_AFTER_ROTATION');
    if((await inspect(address.port,rotated)).status!==200)
      throw Error('NEW_NATIVE_BEARER_REJECTED');
    relay.store.deleteDevice(x.id);
    if((await inspect(address.port,rotated)).status!==403)
      throw Error('DELETED_NATIVE_BEARER_ACCEPTED');
  }
  const anon=await inspect(address.port,'');
  if(anon.status!==403)throw Error('ANONYMOUS_STATUS_ACCEPTED');
  const sandbox=relay.store.issueDeviceToken(
    'h15-hermes-ab005bc0e0ea',admin.id,'Hermes sandbox','linux');
  if((await inspect(address.port,sandbox)).status!==403)
    throw Error('DOCKER_DEVICE_EXPOSED_TO_NATIVE_STATUS');
  const other=relay.store.upsertUser('foreign-owner',secret());
  const foreign=relay.store.issueDeviceToken(
    'h454-win-native-'+'f'.repeat(32),other.id,
    'H454 Windows native read-only','win32');
  if((await inspect(address.port,foreign)).status!==403)
    throw Error('FOREIGN_OWNER_NATIVE_STATUS_ACCEPTED');
  console.log('H454_NATIVE_OWNER_BEARER_REVOCATION_E2E=PASS');
  console.log('H454_REAL_OWNER_HOST_STATUS=NOT_RUN');
}finally{
  await relay.close();
  rmSync(folder,{recursive:true,force:true});
}
