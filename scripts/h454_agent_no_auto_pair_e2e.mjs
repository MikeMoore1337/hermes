// Compiled pinned agent CLI against synthetic 127.0.0.1 relays and credentials.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {createRequire} from 'node:module';
import {spawn} from 'node:child_process';

const agent=path.resolve(process.argv[2] || '');
const cli=path.join(agent,'dist/cli.js');
const {WebSocketServer}=createRequire(path.join(agent,'package.json'))('ws');
const tempRoot=fs.realpathSync(os.tmpdir());
const temp=fs.mkdtempSync(path.join(tempRoot,'h454-no-auto-pair-'));
const identity=fs.lstatSync(temp);
const workspace=path.join(temp,'workspace');fs.mkdirSync(workspace);
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(condition,timeout=10000){
 const deadline=Date.now()+timeout;
 while(Date.now()<deadline){if(condition())return true;await delay(100);}
 return false;
}
async function stop(child){
 if(child.exitCode!==null||child.signalCode!==null)return;
 child.kill('SIGTERM');
 await Promise.race([new Promise(resolve=>child.once('exit',resolve)),delay(3000)]);
 if(child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');await new Promise(resolve=>child.once('exit',resolve));}
}
function start(home,args=[]){
 return spawn(process.execPath,[cli,'--allow-dir',workspace,'--no-browser',...args],
  {env:{PATH:process.env.PATH,HOME:temp,BRC_HOME:home},stdio:'ignore'});
}
function credential(home,url,pairedAt){
 fs.mkdirSync(home,{mode:0o700});
 const body=JSON.stringify({relayUrl:url,deviceId:'synthetic-device',
  deviceToken:'synthetic-not-a-real-token',name:'fixture',pairedAt});
 fs.writeFileSync(path.join(home,'device.json'),body,{mode:0o600});return body;
}

async function denied(pairedAt,status=401){
 let upgrades=0,pairing=0;
 const server=http.createServer((req,res)=>{if(req.url==='/device/start')pairing++;req.resume();res.writeHead(400);res.end();});
 server.on('upgrade',(_req,socket)=>{upgrades++;socket.end(`HTTP/1.1 ${status} Denied\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const home=path.join(temp,`denied-${status}-${pairedAt}`),url=`http://127.0.0.1:${server.address().port}`;
 const before=credential(home,url,pairedAt),child=start(home);
 try{
  assert.ok(await until(()=>upgrades>0),'synthetic 401 was not received');await delay(1200);
  assert.equal(pairing,0,'automatic pairing started');assert.equal(upgrades,1,'unauthorized retry started');
  assert.equal(fs.readFileSync(path.join(home,'device.json'),'utf8'),before,'credential changed');
 }finally{await stop(child);server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
}

async function missingCredential(mismatch=false){
 let requests=0;
 const server=http.createServer((req,res)=>{requests++;req.resume();res.writeHead(400);res.end();});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const home=path.join(temp,mismatch?'mismatch':'missing');
 const before=mismatch?credential(home,'http://127.0.0.1:1','timestamp'):null;
 if(!mismatch)fs.mkdirSync(home,{mode:0o700});
 const child=start(home,['--relay',`http://127.0.0.1:${server.address().port}`,'--device-id','synthetic-device']);
 try{
  assert.ok(await until(()=>child.exitCode!==null),'missing credential did not fail');
  assert.equal(child.exitCode,2);assert.equal(requests,0,'missing credential initiated pairing');
  if(mismatch)assert.equal(fs.readFileSync(path.join(home,'device.json'),'utf8'),before);
 }finally{await stop(child);server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
}

async function deniedAfterHandshake(){
 let upgrades=0,pairing=0,hellos=0;
 const server=http.createServer((req,res)=>{if(req.url==='/device/start')pairing++;req.resume();res.writeHead(400);res.end();});
 const wsServer=new WebSocketServer({noServer:true});const sockets=new Set();
 server.on('upgrade',(req,socket,head)=>{upgrades++;wsServer.handleUpgrade(req,socket,head,ws=>{
  sockets.add(ws);ws.on('close',()=>sockets.delete(ws));
  ws.on('message',data=>{if(JSON.parse(String(data)).type==='hello'){hellos++;ws.close(4401,'denied');}});
 });});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const home=path.join(temp,'denied-close'),url=`http://127.0.0.1:${server.address().port}`;
 const before=credential(home,url,'timestamp'),child=start(home);
 try{
  assert.ok(await until(()=>hellos>0),'synthetic close was not received');await delay(1200);
  assert.equal(pairing,0);assert.equal(upgrades,1);
  assert.equal(fs.readFileSync(path.join(home,'device.json'),'utf8'),before);
 }finally{await stop(child);for(const ws of sockets)ws.terminate();wsServer.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
}

async function reconnect(manual){
 const server=http.createServer();const wsServer=new WebSocketServer({noServer:true});
 let hellos=0;const sockets=new Set();
 server.on('upgrade',(req,socket,head)=>wsServer.handleUpgrade(req,socket,head,ws=>{
  sockets.add(ws);ws.on('close',()=>sockets.delete(ws));
  ws.on('message',data=>{const message=JSON.parse(String(data));if(message.type==='hello'){
    assert.equal(message.device.deviceId,'synthetic-device');hellos++;if(hellos===1)ws.terminate();
  }});
 }));
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const home=path.join(temp,manual?'manual':'saved'),url=`http://127.0.0.1:${server.address().port}`;
 let before,args=[];
 if(manual){fs.mkdirSync(home,{mode:0o700});args=['--relay',url,'--token','synthetic-not-a-real-token','--device-id','synthetic-device'];}
 else before=credential(home,url,'2026-01-01T00:00:00Z');
 const child=start(home,args);
 try{
  assert.ok(await until(()=>hellos>=2,15000),'ordinary reconnect failed');
  if(manual)assert.equal(fs.existsSync(path.join(home,'device.json')),false);
  else assert.equal(fs.readFileSync(path.join(home,'device.json'),'utf8'),before);
 }finally{await stop(child);for(const ws of sockets)ws.terminate();wsServer.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
}

try{
 await denied('timestamp');await denied('manual');await denied('timestamp',403);await deniedAfterHandshake();
 await missingCredential();await missingCredential(true);
 await reconnect(false);await reconnect(true);
 console.log('H454_401_RETAINED_NO_REPAIR=PASS');
 console.log('H454_MISSING_CREDENTIAL_NO_PAIR=PASS');
 console.log('H454_SAVED_AND_MANUAL_RECONNECT=PASS');
 console.log('H454_REAL_CREDENTIALS_USED=FALSE');
}finally{
 const now=fs.lstatSync(temp);
 assert.equal(fs.realpathSync(path.dirname(temp)),tempRoot);
 assert.ok(!now.isSymbolicLink()&&now.dev===identity.dev&&now.ino===identity.ino,'unsafe temporary cleanup');
 fs.rmSync(temp,{recursive:true,force:true});
}
