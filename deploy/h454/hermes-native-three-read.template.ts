/* H454 Stage 2A: three original-host READ endpoints in existing OAuth MCP.
 * No new server, no native shell, no arbitrary deviceId supplied by caller.
 * Pinned real BRC store + authenticated hub socket and exact owner are
 * authorization; agent self-reported hello is NEVER sufficient by itself.
 * Source only until an authorized paired BRC/WSS cutover.
 */
import { createHash } from 'node:crypto';
import type { DeviceHub } from '../device-hub.js';
import type { SqliteStore } from '../store/sqlite.js';
import type { InvokeContext } from './invoke.js';

type Host = 'windows' | 'hermes-vps' | 'yfc-vps';
type Tool = 'native_file_stat' | 'native_file_read' |
            'native_file_list' | 'native_file_search';
type SafeArgs = { project: string; relative: string } |
                { project: string; query: string; mode: string; relative_root: string };
const READ: Tool[] = ['native_file_stat','native_file_read','native_file_list'];
const ALL: Tool[] = [...READ,'native_file_search'];
const PROJECTS = ['hermes','your-fitness-coach','ai-development-toolkit',
                  'financial-horizon','second-brain'];
const HOSTS: Record<Host, {name:string; platform:string; id:RegExp; tools:Tool[]}> = {
  windows: {name:'H454 Windows native read-only', platform:'win32',
    id:/^h454-win-native-[a-f0-9]{32}$/, tools:READ},
  'hermes-vps': {name:'H454 Hermes VPS native read-only', platform:'linux',
    id:/^h454-linux-hermes-[a-f0-9]{32}$/, tools:ALL},
  'yfc-vps': {name:'H454 YFC VPS native read-only', platform:'linux',
    id:/^h454-linux-yfc-[a-f0-9]{32}$/, tools:ALL},
};
const DENY = {content:[{type:'text' as const,
  text:'{"status":"refused","reason":"native_host_read_denied"}'}], isError:true};
const HEX = /^[a-f0-9]{64}$/;
const READ_EXT = /\.(?:py|js|jsx|ts|tsx|mjs|cjs|md|mdx|txt|json|toml|yaml|yml|html|css|scss|sql|sh|ps1|go|rs|c|h|cpp|cs|xml)$/i;
const FORBIDDEN = new Set(['.git','.hg','.svn','.ssh','.aws','.gnupg',
  'vault','.vault','private-vault','secrets','.secrets','credentials',
  'node_modules','__pycache__','.terraform','.next','.cache']);
const SECRET = /(?:^|[._-])(?:secret|credential|token|password|private[-_]?key|api[-_]?key)(?:[._-]|$)/i;

function schema(name:Tool) {
  const search = name === 'native_file_search';
  const host = {type:'string',enum:Object.keys(HOSTS)};
  const project = {type:'string',enum:PROJECTS};
  const fields:Record<string,object> = search
    ? {host,project,query:{type:'string',minLength:1,maxLength:96},
        mode:{type:'string',enum:['names','content']},
        relative_root:{type:'string',maxLength:1024}}
    : {host,project,relative:{type:'string',maxLength:1024}};
  return {name,description:'Original Windows or Linux host source READ only; owner-paired native device required',
    inputSchema:{type:'object',properties:fields,required:Object.keys(fields),
                 additionalProperties:false},
    annotations:{title:name,readOnlyHint:true,destructiveHint:false,openWorldHint:false}};
}
export const NATIVE_THREE_TOOLS = ALL.map(schema);

function safePath(path:string, host:Host, root:boolean):boolean {
  if (typeof path!=='string' || path.length>1024 || (!root && !path)
      || path.startsWith('/') || path.startsWith('\\')
      || path.includes(':') || path.includes('\0') ||
      [...path].some(c=>c.charCodeAt(0)<32)) return false;
  if (root && !path) return true;
  const sep = host==='windows'?'\\':'/';
  const foreign = host==='windows'?'/':'\\';
  if (path.includes(foreign))return false;
  const parts=path.split(sep);
  return parts.every(part=>part && part!=='.' && part!=='..'
    && !part.endsWith('.') && !part.endsWith(' ')
    && !FORBIDDEN.has(part.toLowerCase())
    && !part.toLowerCase().startsWith('.env')
    && !SECRET.test(part)
    && !/(?:\.pem|\.key|\.p12|\.pfx|\.kdbx|\.sqlite3?|\.db)$/i.test(part)
    && (host!=='windows' || !/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i.test(part)));
}
function safeArgs(method:Tool, raw:unknown):{host:Host;args:SafeArgs}|null {
  if (!raw || typeof raw!=='object'||Array.isArray(raw))return null;
  const o=raw as Record<string,unknown>;
  const host=o.host;
  if (typeof host!=='string'||!Object.hasOwn(HOSTS,host))return null;
  const target=host as Host;
  if (!HOSTS[target].tools.includes(method)||typeof o.project!=='string'
      || !PROJECTS.includes(o.project))return null;
  if (method==='native_file_search') {
    if (Object.keys(o).sort().join(',')!=='host,mode,project,query,relative_root'
        || typeof o.query!=='string'||o.query.length<1||o.query.length>96
        || typeof o.mode!=='string'||!['names','content'].includes(o.mode)
        || typeof o.relative_root!=='string'||!safePath(o.relative_root,target,true)
        || [...o.query].some(c=>c.charCodeAt(0)<32))return null;
    return {host:target,args:{project:o.project,query:o.query,
      mode:o.mode,relative_root:o.relative_root}};
  }
  if (Object.keys(o).sort().join(',')!=='host,project,relative'
      || typeof o.relative!=='string'
      || (method==='native_file_list'&&target==='windows'&&o.relative!=='')
      || !safePath(o.relative,target,method!=='native_file_read')
      || (method==='native_file_read'&&!READ_EXT.test(o.relative)))return null;
  return {host:target,args:{project:o.project,relative:o.relative}};
}

function ownerDevice(hub:DeviceHub, store:SqliteStore, owner:string, host:Host):string|null {
  try {
    const p=HOSTS[host], rows=store.listDevices(owner).filter(d=>
      d.name===p.name || (typeof d.device_id==='string' && p.id.test(d.device_id)));
    if (rows.length!==1)return null;
    const d=rows[0];
    if (!p.id.test(d.device_id)||d.name!==p.name||d.platform!==p.platform||d.paused
        ||typeof d.token_hash!=='string'||!HEX.test(d.token_hash))return null;
    const live=hub.get(d.device_id);
    const socket=live?.socket as (typeof live.socket & {hermesAuthTokenHash?:string})|undefined;
    if (!live||!socket||socket.hermesAuthTokenHash!==d.token_hash
        ||live.ownerId!==owner||live.info.deviceId!==d.device_id
        ||live.info.name!==p.name||live.info.platform!==p.platform
        ||!Array.isArray(live.tools)||live.tools.length!==p.tools.length
        ||new Set(live.tools.map(t=>t.name)).size!==p.tools.length
        ||live.tools.some(t=>!p.tools.includes(t.name as Tool)))return null;
    return d.device_id;
  }catch{return null;}
}
function validResult(value:unknown, method:Tool, args:SafeArgs, host:Host):boolean {
  if(!value||typeof value!=='object'||Array.isArray(value))return false;
  const v=value as Record<string,unknown>;
  if(v.status!=='ok'||v.project!==args.project)return false;
  if(method==='native_file_search'){
    const a=args as {relative_root:string;mode:string};
    if(v.relative_root!==a.relative_root||v.mode!==a.mode
        ||typeof v.truncated!=='boolean'||!Number.isInteger(v.entries_scanned)
        ||(v.entries_scanned as number)>512||(v.entries_scanned as number)<0
        ||!Number.isInteger(v.bytes_scanned)||(v.bytes_scanned as number)>2097152
        ||(v.bytes_scanned as number)<0
        ||!Array.isArray(v.matches)||v.matches.length>64)return false;
    return v.matches.every((m:unknown)=>{
      if(!m||typeof m!=='object'||Array.isArray(m))return false;
      const row=m as Record<string,unknown>;
      if(typeof row.path!=='string'||!safePath(row.path,host,false))return false;
      if(a.relative_root&&!row.path.startsWith(a.relative_root+'/'))return false;
      return a.mode==='names' ? Object.keys(row).sort().join(',')==='kind,path'
        && ['file','directory'].includes(row.kind as string)
        : Object.keys(row).sort().join(',')==='line,path'
          && Number.isSafeInteger(row.line)&&(row.line as number)>0;
    });
  }
  const a=args as {relative:string};
  if(v.relative!==a.relative||v.action!==method.slice('native_file_'.length))return false;
  if(method==='native_file_list') {
    if(v.kind!=='directory'||typeof v.truncated!=='boolean'
      ||!Array.isArray(v.entries)||v.entries.length>64)return false;
    const seen=new Set<string>();
    for(const item of v.entries){
      if(!item||typeof item!=='object'||Array.isArray(item))return false;
      const row=item as Record<string,unknown>;
      if(Object.keys(row).sort().join(',')!=='kind,name'
        ||!['file','directory'].includes(row.kind as string)
        ||typeof row.name!=='string'
        ||!safePath(row.name,host,false)
        ||row.name.includes('/')||row.name.includes('\\'))return false;
      const key=host==='windows'?row.name.toLowerCase():row.name;
      if(seen.has(key))return false;
      seen.add(key);
    }
    return true;
  }
  if(!['file','directory'].includes(v.kind as string))return false;
  if(method==='native_file_stat'){
    return v.kind==='directory' ? v.size_bytes===null
      : Number.isSafeInteger(v.size_bytes)&&(v.size_bytes as number)>=0;
  }
  if(v.kind!=='file'||v.encoding!=='base64'||!Number.isSafeInteger(v.size_bytes)
      ||(v.size_bytes as number)<0||(v.size_bytes as number)>262144
      ||typeof v.sha256!=='string'||!HEX.test(v.sha256)
      ||typeof v.data!=='string'||v.data.length>349528
      ||!/^[A-Za-z0-9+/]*={0,2}$/.test(v.data)||v.data.length%4!==0)return false;
  const data=Buffer.from(v.data,'base64');
  return data.length===v.size_bytes && data.toString('base64')===v.data
    && createHash('sha256').update(data).digest('hex')===v.sha256;
}

export async function invokeOwnerNativeThreeRead(
    hub:DeviceHub,store:SqliteStore,ctx:InvokeContext,
    name:string,input:unknown) {
  if(!ALL.includes(name as Tool))return DENY;
  const tool=name as Tool;
  const checked=safeArgs(tool,input);
  if(!checked)return DENY;
  const deviceId=ownerDevice(hub,store,ctx.userId,checked.host);
  if(!deviceId)return DENY;
  const started=Date.now();
  const argsHash=createHash('sha256').update(JSON.stringify(
      {host:checked.host,tool,args:checked.args})).digest('hex').slice(0,16);
  let result:Record<string,unknown>|null=null;
  try {
    const response=await hub.call(deviceId,tool,checked.args,{
      client:{name:ctx.clientId},timeoutMs:8000,
    });
    if(response && !response.isError && Array.isArray(response.content)
       && response.content.length===1&&response.content[0]?.type==='text'
       && typeof response.content[0].text==='string'
       && response.content[0].text.length<=370000){
      const raw=JSON.parse(response.content[0].text);
      const wrapped=checked.host==='windows' ? raw :
        raw && raw.status==='ok' && raw.tool===tool
        && typeof raw.id==='string' && raw.id.length>0 ? raw.result : null;
      if(validResult(wrapped,tool,checked.args,checked.host))
        result=wrapped as Record<string,unknown>;
    }
  }catch{ /* Never forward original host exception paths or socket errors. */ }
  if(ownerDevice(hub,store,ctx.userId,checked.host)!==deviceId)result=null;
  try {
    store.audit({ts:started,user_id:ctx.userId,device_id:deviceId,
      client:ctx.clientId,tool:tool,args_hash:argsHash,ok:result?1:0,
      ms:Date.now()-started,error:result?null:'NATIVE_HOST_READ_DENIED'});
  }catch{return DENY;}
  // Revocation and deletion may race both remote call and audit.
  if(ownerDevice(hub,store,ctx.userId,checked.host)!==deviceId)return DENY;
  return result ? {content:[{type:'text' as const,text:JSON.stringify(result)}],
    isError:false} : DENY;
}
