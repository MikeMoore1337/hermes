#!/usr/bin/env node
// Hermes #454: invoke the compiled EXISTING MCP relay's new native dispatcher
// against three strictly synthetic owner/device records. No owner host IO.
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';

const root=process.cwd();
const url=pathToFileURL(path.join(root,
  'packages/relay/dist/mcp/hermes-native-three-read.js')).href;
const {NATIVE_THREE_TOOLS,invokeOwnerNativeThreeRead}=await import(url);
const assert=(check,why)=>{if(!check)throw Error(why);};
const ctx={userId:'owner-1',clientId:'chatgpt-fixture'};
const profiles=[
 {host:'windows',name:'H454 Windows native read-only',id:'h454-win-native-'+'a'.repeat(32),platform:'win32',n:3},
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
const store={
  listDevices(owner){return owner===ctx.userId?rows:[];},
  audit(record){audited.push(record);},
};
let calls=0, revokeNext=false, malformed=false;
const hub={
  get(id){return devices.get(id);},
  async call(id,tool,args,opts){
    calls++;
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
      payload={status:'ok',project:args.project,relative_root:'',
        mode:'names',matches:[{path:'src',kind:'directory'}],
        entries_scanned:1,bytes_scanned:0,truncated:false};
    }else throw Error('UNEXPECTED_TOOL');
    if(malformed)payload.secret='should-not-leak';
    if(revokeNext) rows.find(r=>r.device_id===id).paused=1;
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
  if(p.host==='windows'){
    assert(denied(await invokeOwnerNativeThreeRead(hub,store,ctx,
      'native_file_search',{host:'windows',project:'hermes',query:'src',
         mode:'names',relative_root:''})), 'WINDOWS_SEARCH_MISADVERTISED');
  }else{
    const found=await invokeOwnerNativeThreeRead(hub,store,ctx,
      'native_file_search',{host:p.host,project:'hermes',query:'src',
         mode:'names',relative_root:''});
    assert(!found.isError,'NATIVE_LINUX_SEARCH_REFUSED_'+p.host);
  }
}
assert(audited.length>=profiles.length,'NO_AUDIT');
assert(audited.every(x=>x.user_id===ctx.userId&&
  typeof x.args_hash==='string'&&x.args_hash.length===16),
  'AUDIT_PRIVACY_OR_OWNER_MISMATCH');
console.log('H454_THREE_NATIVE_MCP_ROUTE_E2E=PASS');
console.log('H454_OWNER_ORIGINAL_HOSTS=NOT_RUN');
