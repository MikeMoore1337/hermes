#!/usr/bin/env node
// Hermes #454: invoke the compiled EXISTING MCP relay's new native dispatcher
// against three strictly synthetic owner/device records. No owner host IO.
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';

const root=process.cwd();
const url=pathToFileURL(path.join(root,
  'packages/relay/dist/mcp/hermes-native-three-read.js')).href;
const {NATIVE_THREE_TOOLS,invokeOwnerNativeThreeRead}=await import(url);
const assert=(check,why)=>{if(!check)throw Error(why);};
const repository=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const python=spawnSync(process.env.H454_TEST_PYTHON || 'python3',['-B','-m','tests.h454_native_wire_fixture'],
  {cwd:repository,encoding:'utf8',timeout:10000,windowsHide:true});
assert(python.status===0,'ACTUAL_PYTHON_WIRE_FIXTURE_FAILED');
const actualLinuxRead=JSON.parse(python.stdout);
const ctx={userId:'owner-1',clientId:'chatgpt-fixture'};
const profiles=[
 {host:'windows',name:'H454 Windows native read-only',id:'h454-win-native-'+'a'.repeat(32),platform:'win32',n:4},
 {host:'hermes-vps',name:'H454 Hermes VPS native read-only',id:'h454-linux-hermes-'+'b'.repeat(32),platform:'linux',n:4},
 {host:'yfc-vps',name:'H454 YFC VPS native read-only',id:'h454-linux-yfc-'+'c'.repeat(32),platform:'linux',n:4},
];
const SHA=createHash('sha256').update('abc').digest('hex');
const denied=(response)=>response?.isError===true
  && JSON.stringify(response).includes('native_host_read_denied');
assert(NATIVE_THREE_TOOLS.length===4,'EXACT_TOOL_CATALOG');
assert(new Set(NATIVE_THREE_TOOLS.map(x=>x.name)).size===4,'NO_DUPLICATES');
const rows=profiles.map(p=>({device_id:p.id,user_id:ctx.userId,name:p.name,
    platform:p.platform,paused:0,token_hash:'f'.repeat(64)}));
const devices=new Map(profiles.map(p=>[p.id,{
    ownerId:ctx.userId,
    info:{deviceId:p.id,name:p.name,platform:p.platform,arch:'x64'},
    tools:(p.n===3
      ? ['native_file_stat','native_file_read','native_file_list']
      : ['native_file_stat','native_file_read','native_file_list','native_file_search'])
      .map(name=>({name})),
    socket:{hermesAuthTokenHash:'f'.repeat(64)},
}]));
const audited=[];
let rotateDuringAudit=false;
const store={
  listDevices(owner){return rows.filter(row=>row.user_id===owner);},
  audit(record){
    audited.push(record);
    if(rotateDuringAudit){
      rows.find(r=>r.device_id===record.device_id).token_hash='1'.repeat(64);
      devices.get(record.device_id).socket.hermesAuthTokenHash='1'.repeat(64);
    }
  },
};
let calls=0, revokeNext=false, rotateNext=false, malformed=false, escapeSearch=false, failCall=false;
const hub={
  get(id){return devices.get(id);},
  async call(id,tool,args,opts){
    calls++;
    if(failCall)throw Error('synthetic uncertain result');
    assert(opts.timeoutMs===8000,'BOUNDED_TIME');
    assert(opts.client.name===ctx.clientId,'CLIENT_BOUND');
    assert(!('host' in args),'HOST_NOT_SENT_TO_AGENT');
    const row=profiles.find(p=>p.id===id);
    assert(row,'UNKNOWN_DEVICE_ROUTE');
    let payload;
    if(tool==='native_file_read'){
      payload={status:'ok',project:args.project,relative:args.relative,
        action:'read',kind:'file',size_bytes:3,
        encoding:'base64',data:'YWJj',sha256:SHA};
    } else if(tool==='native_file_search'){
      const child=args.relative_root+(row.host==='windows'?'\\':'/')+'safe.py';
      payload={status:'ok',project:args.project,relative_root:args.relative_root,
        mode:'names',matches:[{path:args.relative_root&&!escapeSearch?child:'src',
          kind:args.relative_root&&!escapeSearch?'file':'directory'}],
        entries_scanned:1,bytes_scanned:0,truncated:false};
    }else throw Error('UNEXPECTED_TOOL');
    if(malformed)payload.secret='should-not-leak';
    if(revokeNext) rows.find(r=>r.device_id===id).paused=1;
    if(rotateNext){
      rows.find(r=>r.device_id===id).token_hash='1'.repeat(64);
      devices.get(id).socket.hermesAuthTokenHash='1'.repeat(64);
    }
    if(row.host==='hermes-vps' && tool==='native_file_read' && !malformed && !revokeNext)
      return actualLinuxRead;
    const value=row.host==='windows' ? payload
      : {status:'ok',tool,id:'call-id-1',result:payload};
    return {isError:false,content:[{type:'text',text:JSON.stringify(value)}]};
  },
};

for(const p of profiles){
  const args={host:p.host,project:'hermes',relative:'README.md'};
  const got=await invokeOwnerNativeThreeRead(hub,store,ctx,
    'native_file_read',args);
  assert(!got.isError,'VALID_NATIVE_READ_REFUSED_'+p.host);
  const value=JSON.parse(got.content[0].text);
  assert(value.sha256===SHA&&value.data==='YWJj','BODY_NOT_VALIDATED');
  for(const wrong of [
    {...args,deviceId:'h15-win-05be75515428'},
    {...args,approved:true},
    {...args,relative:'../private.md'},
    {...args,relative:'.env'},
    {...args,relative:'vault/secret.md'},
    {...args,project:'unknown'},
  ]){
    assert(denied(await invokeOwnerNativeThreeRead(hub,store,ctx,
      'native_file_read',wrong)), 'UNSAFE_NATIVE_ARGUMENT_ACCEPTED');
  }
  const row=rows.find(x=>x.device_id===p.id);
  row.paused=1;
  assert(denied(await invokeOwnerNativeThreeRead(hub,store,ctx,
    'native_file_read',args)), 'PAUSED_DEVICE_ALLOWED');
  row.paused=0;
  const live=devices.get(p.id);
  live.socket.hermesAuthTokenHash='0'.repeat(64);
  assert(denied(await invokeOwnerNativeThreeRead(hub,store,ctx,
    'native_file_read',args)), 'STALE_TOKEN_SOCKET_ALLOWED');
  live.socket.hermesAuthTokenHash='f'.repeat(64);
  malformed=true;
  assert(denied(await invokeOwnerNativeThreeRead(hub,store,ctx,
    'native_file_read',args)), 'UNEXPECTED_DATA_FIELD_ACCEPTED');
  malformed=false;
  revokeNext=true;
  assert(denied(await invokeOwnerNativeThreeRead(hub,store,ctx,
    'native_file_read',args)), 'MIDFLIGHT_REVOCATION_ALLOWED');
  revokeNext=false;
  row.paused=0;
  {
    const found=await invokeOwnerNativeThreeRead(hub,store,ctx,
      'native_file_search',{host:p.host,project:'hermes',query:'src',
         mode:'names',relative_root:''});
    assert(!found.isError,'NATIVE_SEARCH_REFUSED_'+p.host);
    const nested={host:p.host,project:'hermes',query:'safe',mode:'names',relative_root:'different'};
    assert(!(await invokeOwnerNativeThreeRead(hub,store,ctx,
      'native_file_search',nested)).isError, 'NESTED_SEARCH_REFUSED_'+p.host);
    escapeSearch=true;
    assert(denied(await invokeOwnerNativeThreeRead(hub,store,ctx,
      'native_file_search',nested)), 'SEARCH_ROOT_ESCAPE_ACCEPTED');
    escapeSearch=false;
  }
}

// Calls arriving during the owner's brief disconnect wait before dispatch.
// They are never replayed after dispatch, and every identity change fails closed.
const yfc=profiles.find(p=>p.host==='yfc-vps');
const yfcRow=rows.find(r=>r.device_id===yfc.id);
const yfcLive=devices.get(yfc.id);
const request={host:yfc.host,project:'hermes',relative:'README.md'};
devices.delete(yfc.id);
let before=calls;
const waiting=invokeOwnerNativeThreeRead(hub,store,ctx,'native_file_read',request);
setTimeout(()=>devices.set(yfc.id,yfcLive),100);
assert(!(await waiting).isError && calls===before+1,'RECONNECT_WAIT_MUST_DISPATCH_ONCE');

devices.delete(yfc.id);
before=calls;
const revoked=invokeOwnerNativeThreeRead(hub,store,ctx,'native_file_read',request);
setTimeout(()=>{yfcRow.paused=1;},100);
assert(denied(await revoked) && calls===before,'REVOKED_WHILE_WAITING');
yfcRow.paused=0;

const changedToken=invokeOwnerNativeThreeRead(hub,store,ctx,'native_file_read',request);
setTimeout(()=>{yfcRow.token_hash='1'.repeat(64);},100);
assert(denied(await changedToken) && calls===before,'TOKEN_CHANGED_WHILE_WAITING');
yfcRow.token_hash='f'.repeat(64);

const duplicate=invokeOwnerNativeThreeRead(hub,store,ctx,'native_file_read',request);
setTimeout(()=>{rows.push({...yfcRow});},100);
assert(denied(await duplicate) && calls===before,'AMBIGUOUS_OWNER_WHILE_WAITING');
rows.pop();

const forged=invokeOwnerNativeThreeRead(hub,store,ctx,'native_file_read',request);
setTimeout(()=>devices.set(yfc.id,{...yfcLive,ownerId:'other-owner'}),100);
assert(denied(await forged) && calls===before,'FORGED_RECONNECT_MUST_NOT_DISPATCH');
devices.delete(yfc.id);

const bounded=Array.from({length:4},()=>invokeOwnerNativeThreeRead(hub,store,ctx,'native_file_read',request));
assert(denied(await invokeOwnerNativeThreeRead(hub,store,ctx,'native_file_read',request)),
  'OWNER_WAIT_LIMIT_NOT_ENFORCED');
setTimeout(()=>devices.set(yfc.id,yfcLive),100);
assert((await Promise.all(bounded)).every(result=>!result.isError),'BOUNDED_WAIT_RECOVERY_FAILED');
assert(calls===before+4,'BOUNDED_WAIT_DISPATCH_COUNT');

// Different owners cannot fill an unbounded number of pending requests either.
const extraRows=Array.from({length:5},(_,i)=>({
  ...yfcRow,user_id:'extra-owner-'+i,device_id:'h454-linux-yfc-'+String(i+1).repeat(32),
}));
rows.push(...extraRows);
const globalPending=extraRows.slice(0,4).flatMap(row=>Array.from({length:4},()=>
  invokeOwnerNativeThreeRead(hub,store,{userId:row.user_id,clientId:'synthetic'},'native_file_read',request)));
assert(denied(await invokeOwnerNativeThreeRead(hub,store,
  {userId:extraRows[4].user_id,clientId:'synthetic'},'native_file_read',request)),
  'GLOBAL_WAIT_LIMIT_NOT_ENFORCED');
for(const row of extraRows)row.paused=1;
assert((await Promise.all(globalPending)).every(denied),'GLOBAL_WAIT_REVOCATION_NOT_ENFORCED');
rows.splice(rows.length-extraRows.length,extraRows.length);

failCall=true;
before=calls;
assert(denied(await invokeOwnerNativeThreeRead(hub,store,ctx,'native_file_read',request)),
  'UNCERTAIN_DISPATCH_MUST_FAIL_CLOSED');
assert(calls===before+1,'UNCERTAIN_DISPATCH_MUST_NOT_RETRY');
failCall=false;

rotateNext=true;
assert(denied(await invokeOwnerNativeThreeRead(hub,store,ctx,'native_file_read',request)),
  'MIDFLIGHT_TOKEN_ROTATION_ALLOWED');
rotateNext=false;
yfcRow.token_hash=yfcLive.socket.hermesAuthTokenHash='f'.repeat(64);
rotateDuringAudit=true;
assert(denied(await invokeOwnerNativeThreeRead(hub,store,ctx,'native_file_read',request)),
  'TOKEN_ROTATION_DURING_AUDIT_ALLOWED');
rotateDuringAudit=false;
yfcRow.token_hash=yfcLive.socket.hermesAuthTokenHash='f'.repeat(64);

devices.delete(yfc.id);
before=calls;
assert(denied(await invokeOwnerNativeThreeRead(hub,store,ctx,'native_file_read',request)),
  'OFFLINE_WAIT_MUST_EXPIRE');
assert(calls===before,'OFFLINE_WAIT_MUST_NOT_DISPATCH');
devices.set(yfc.id,yfcLive);
assert(audited.length>=profiles.length,'NO_AUDIT');
assert(audited.every(x=>x.user_id===ctx.userId&&
  typeof x.args_hash==='string'&&x.args_hash.length===16),
  'AUDIT_PRIVACY_OR_OWNER_MISMATCH');
console.log('H454_THREE_NATIVE_MCP_ROUTE_E2E=PASS');
console.log('H454_OWNER_ORIGINAL_HOSTS=NOT_RUN');
