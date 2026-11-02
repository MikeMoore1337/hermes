// The legacy agent sees only a local surrogate; its real bearer stays in this container.
import { createHash, timingSafeEqual } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import { pathToFileURL } from 'node:url';
import { isolatedIPv4, isolatedNetwork, ipv4Number, privateIPv4, readPinnedCa } from './h454_isolated_rollback_proxy.mjs';

export const SURROGATE = 'brc_dev_' + 's'.repeat(43);
const TOKEN = /^brc_dev_[A-Za-z0-9_-]{40,256}$/;
const SERVER_NAME = 'brc-agent.internal';
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export function createCredentialBroker({ upstreamHost, upstreamPort, ca }) {
  if (net.isIP(upstreamHost) !== 4 || !Number.isInteger(upstreamPort) || upstreamPort < 1 ||
      upstreamPort > 65535 || !Buffer.isBuffer(ca) || ca.length < 1 || ca.length > 65536)
    throw Error('H454_BROKER_CONFIGURATION');
  let bearer = null, active = false;
  const staging = net.createServer({ allowHalfOpen:true }, socket => {
    if (socket.remoteAddress !== '127.0.0.1') { socket.destroy(); return; }
    const chunks = []; let size = 0;
    socket.setTimeout(5000, () => socket.destroy());
    socket.on('error', () => {});
    socket.on('data', chunk => {
      size += chunk.length;
      if (size > 264) { socket.destroy(); return; }
      chunks.push(chunk);
    });
    socket.on('end', () => {
      const input = Buffer.concat(chunks);
      const text = input.toString('utf8');
      const valid = TOKEN.test(text) && text !== SURROGATE;
      const matches = bearer === null || (bearer.length === input.length && timingSafeEqual(bearer, input));
      if (valid && matches) {
        if (bearer === null) bearer = Buffer.from(input);
        socket.end('H454_BROKER_TOKEN_STAGED');
      } else socket.end('H454_BROKER_TOKEN_REFUSED');
      input.fill(0); for (const chunk of chunks) chunk.fill(0);
    });
  });
  staging.maxConnections = 2;

  const server = http.createServer({ maxHeaderSize:8192 }, (_request, response) => {
    response.writeHead(404, { Connection:'close' }); response.end();
  });
  server.maxConnections = 4;
  server.headersTimeout = 10000;
  server.requestTimeout = 15000;
  server.on('clientError', (_error, socket) => socket.destroy());
  server.on('upgrade', (request, client, head) => {
    const names = request.rawHeaders.filter((_, i) => i % 2 === 0).map(v => v.toLowerCase());
    const once = name => names.filter(v => v === name).length === 1;
    const h = request.headers;
    const valid = bearer !== null && !active && request.method === 'GET' && request.url === '/ws' &&
      request.httpVersion === '1.1' && head.length === 0 &&
      ['authorization', 'upgrade', 'connection', 'sec-websocket-key', 'sec-websocket-version',
        'x-brc-protocol'].every(once) && h.authorization === `Bearer ${SURROGATE}` &&
      /^websocket$/i.test(h.upgrade || '') && /^upgrade$/i.test(h.connection || '') &&
      /^[A-Za-z0-9+/]{22}==$/.test(h['sec-websocket-key'] || '') &&
      h['sec-websocket-version'] === '13' && h['x-brc-protocol'] === '1';
    if (!valid) { client.destroy(); return; }
    active = true;
    client.setTimeout(120000, () => client.destroy());
    client.on('error', () => {});
    const upstream = https.request({ host:upstreamHost, port:upstreamPort, path:'/ws', method:'GET',
      agent:false, ca, servername:SERVER_NAME, rejectUnauthorized:true, minVersion:'TLSv1.2',
      headers:{ Connection:'Upgrade', Upgrade:'websocket', Authorization:`Bearer ${bearer.toString('ascii')}`,
        'Sec-WebSocket-Key':h['sec-websocket-key'], 'Sec-WebSocket-Version':'13', 'X-BRC-Protocol':'1' } });
    upstream.setTimeout(5000, () => upstream.destroy());
    upstream.on('error', () => client.destroy());
    client.once('close', () => { active = false; upstream.destroy(); });
    upstream.on('response', response => {
      const status = response.statusCode === 401 ? '401 Unauthorized' :
        response.statusCode === 403 ? '403 Forbidden' : '502 Bad Gateway';
      client.end(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
      response.resume();
    });
    upstream.on('upgrade', (response, peer, upstreamHead) => {
      const accept = createHash('sha1').update(h['sec-websocket-key'] + WS_GUID).digest('base64');
      if (client.destroyed || response.statusCode !== 101 || response.headers['sec-websocket-accept'] !== accept ||
          !/^websocket$/i.test(response.headers.upgrade || '') || !/^upgrade$/i.test(response.headers.connection || '')) {
        peer.destroy(); client.destroy(); return;
      }
      peer.on('error', () => client.destroy());
      client.once('close', () => peer.destroy());
      peer.once('close', () => client.destroy());
      client.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n' +
        `Upgrade: websocket\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
      if (upstreamHead.length) client.write(upstreamHead);
      client.pipe(peer).pipe(client);
    });
    upstream.end();
  });
  return { server, staging };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 5 || !privateIPv4(process.argv[2])) throw Error('H454_BROKER_ARGUMENTS');
    const network = isolatedNetwork(process.argv[4]);
    if (((ipv4Number(process.argv[2]) & network.mask) >>> 0) === network.base) throw Error('H454_BROKER_ROUTE');
    const listenHost = isolatedIPv4(os.networkInterfaces(), process.argv[4]);
    const ca = readPinnedCa(process.argv[3]);
    const broker = createCredentialBroker({ upstreamHost:process.argv[2], upstreamPort:38184, ca });
    const fail = () => { console.error('H454_BROKER_ERROR'); process.exit(1); };
    broker.staging.on('error', fail); broker.server.on('error', fail);
    broker.staging.listen(38181, '127.0.0.1', () =>
      broker.server.listen(38180, listenHost, () => console.log('H454_BROKER_READY')));
  } catch {
    console.error('H454_BROKER_REFUSED');
    process.exitCode = 1;
  }
}
