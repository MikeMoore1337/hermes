// Private TLS front end for the existing relay's agent WebSocket only.
import { readFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { pathToFileURL } from 'node:url';

export function privateIPv4(address) {
  if (typeof address !== 'string' || net.isIP(address) !== 4) return false;
  const [a, b] = address.split('.').map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

export function relayHealthy(port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('UPSTREAM_PORT');
  return new Promise(resolve => {
    let done = false;
    const finish = ok => { if (!done) { done = true; resolve(ok); } };
    const request = http.get({ host: '127.0.0.1', port, path: '/health', agent: false }, response => {
      finish(response.statusCode === 200);
      response.destroy();
    });
    request.on('error', () => finish(false));
    request.setTimeout(2000, () => request.destroy());
  });
}

export function relayWatchdog(probe, onLost) {
  let failures = 0, running = false, lost = false;
  return async () => {
    if (running || lost) return;
    running = true;
    let healthy = false;
    try { healthy = await probe() === true; } catch {}
    finally { running = false; }
    failures = healthy ? 0 : failures + 1;
    if (failures >= 3) { lost = true; onLost(); }
  };
}

export function createProxy({ key, cert, upstreamPort, allowedPeer }) {
  if (!Number.isInteger(upstreamPort) || upstreamPort < 1 || upstreamPort > 65535 ||
      typeof allowedPeer !== 'string' || net.isIP(allowedPeer) !== 4 || allowedPeer === '0.0.0.0')
    throw new Error('H454_PROXY_CONFIGURATION');
  const server = https.createServer({ key, cert, minVersion: 'TLSv1.2', maxHeaderSize: 8192,
    handshakeTimeout: 10000 },
    (_req, res) => { res.writeHead(404, { Connection: 'close' }); res.end(); });
  server.maxConnections = 8;
  server.prependListener('connection', socket => { if (socket.remoteAddress !== allowedPeer) socket.destroy(); });
  server.headersTimeout = 10000;
  server.requestTimeout = 15000;
  server.on('tlsClientError', () => {});
  server.on('upgrade', (req, client, head) => {
    const names = req.rawHeaders.filter((_, i) => i % 2 === 0).map(v => v.toLowerCase());
    const once = name => names.filter(v => v === name).length === 1;
    const h = req.headers;
    const valid = req.method === 'GET' && req.url === '/ws' && req.httpVersion === '1.1' &&
      head.length === 0 && ['authorization', 'upgrade', 'connection', 'sec-websocket-key',
        'sec-websocket-version', 'x-brc-protocol'].every(once) &&
      /^Bearer brc_dev_[A-Za-z0-9_-]{40,256}$/.test(h.authorization || '') &&
      /^websocket$/i.test(h.upgrade || '') && /^upgrade$/i.test(h.connection || '') &&
      /^[A-Za-z0-9+/]{22}==$/.test(h['sec-websocket-key'] || '') &&
      h['sec-websocket-version'] === '13' && h['x-brc-protocol'] === '1';
    if (!valid) { client.destroy(); return; }

    client.setTimeout(120000, () => client.destroy());
    client.on('error', () => {});
    const request = http.request({ host: '127.0.0.1', port: upstreamPort, path: '/ws',
      method: 'GET', agent: false, headers: {
        Connection: 'Upgrade', Upgrade: 'websocket', Authorization: h.authorization,
        'Sec-WebSocket-Key': h['sec-websocket-key'], 'Sec-WebSocket-Version': '13',
        'X-BRC-Protocol': '1',
      } });
    request.setTimeout(5000, () => request.destroy());
    request.on('error', () => client.destroy());
    client.once('close', () => request.destroy());
    request.on('response', response => {
      const status = response.statusCode === 401 ? '401 Unauthorized' :
        response.statusCode === 403 ? '403 Forbidden' : '502 Bad Gateway';
      client.end(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
      response.resume();
    });
    request.on('upgrade', (response, upstream, upstreamHead) => {
      const accept = response.headers['sec-websocket-accept'];
      if (client.destroyed || response.statusCode !== 101 || typeof accept !== 'string' ||
          !/^[A-Za-z0-9+/]{27}=$/.test(accept)) { upstream.destroy(); client.destroy(); return; }
      upstream.on('error', () => client.destroy());
      client.once('close', () => upstream.destroy());
      upstream.once('close', () => client.destroy());
      client.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n' +
                   `Upgrade: websocket\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
      if (upstreamHead.length) client.write(upstreamHead);
      client.pipe(upstream).pipe(client);
    });
    request.end();
  });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const allowedPeer = process.env.H454_SSH_SOURCE_IPV4;
    if (!privateIPv4(allowedPeer)) throw new Error('H454_SSH_SOURCE_IPV4');
    const server = createProxy({ key: readFileSync('/run/h454-wss/relay.key'),
      cert: readFileSync('/run/h454-wss/relay.crt'), upstreamPort: 3000, allowedPeer });
    server.on('error', () => { console.error('H454_WSS_PROXY_ERROR'); process.exitCode = 1; });
    const watch = relayWatchdog(() => relayHealthy(3000), () => {
      console.error('H454_WSS_RELAY_LOST');
      process.exit(1);
    });
    const timer = setInterval(watch, 5000);
    timer.unref();
    server.once('close', () => clearInterval(timer));
    server.listen(3001, '0.0.0.0');
  } catch {
    console.error('H454_WSS_PROXY_START_FAILED');
    process.exitCode = 1;
  }
}
