// Narrow TCP-to-pinned-TLS bridge for an owner-approved isolated rollback.
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import tls from 'node:tls';
import { pathToFileURL } from 'node:url';

const SERVER_NAME = 'brc-agent.internal';
const CA_PATH = '/opt/hermes-rollback/relay-ca.pem';

function privateIPv4(address) {
  if (net.isIP(address) !== 4) return false;
  const [a, b] = address.split('.').map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function ipv4Number(address) {
  return address.split('.').reduce((value, octet) => value * 256 + Number(octet), 0);
}

function isolatedNetwork(cidr) {
  if (typeof cidr !== 'string' || !/^(?:\d{1,3}\.){3}\d{1,3}\/(?:[8-9]|[12]\d|30)$/.test(cidr))
    throw Error('H454_ISOLATED_NETWORK');
  const [address, bits] = cidr.split('/'), prefix = Number(bits);
  if (!privateIPv4(address)) throw Error('H454_ISOLATED_NETWORK');
  const mask = (0xffffffff << (32 - prefix)) >>> 0, base = ipv4Number(address);
  const end = (base | (~mask >>> 0)) >>> 0;
  const last = [end >>> 24, (end >>> 16) & 255, (end >>> 8) & 255, end & 255].join('.');
  if (((base & mask) >>> 0) !== base || !privateIPv4(last)) throw Error('H454_ISOLATED_NETWORK');
  return { base, mask, prefix };
}

export function isolatedIPv4(interfaces, cidr) {
  const network = isolatedNetwork(cidr);
  const addresses = Object.values(interfaces).flatMap(entries => entries ?? [])
    .filter(entry => entry && !entry.internal && entry.family === 'IPv4');
  if (addresses.length < 1 || addresses.length > 2 || addresses.some(entry => !privateIPv4(entry.address)))
    throw Error('H454_ISOLATED_INTERFACE');
  const matching = addresses.filter(entry => ((ipv4Number(entry.address) & network.mask) >>> 0) === network.base &&
    entry.cidr === `${entry.address}/${network.prefix}`);
  if (matching.length !== 1 || addresses.filter(entry =>
    ((ipv4Number(entry.address) & network.mask) >>> 0) === network.base).length !== 1)
    throw Error('H454_ISOLATED_INTERFACE');
  return matching[0].address;
}

export function createRollbackProxy({ upstreamHost, upstreamPort, ca }) {
  if (net.isIP(upstreamHost) !== 4 || !Number.isInteger(upstreamPort) || upstreamPort < 1 || upstreamPort > 65535 ||
      !Buffer.isBuffer(ca) || ca.length < 1 || ca.length > 65536) throw Error('H454_PROXY_CONFIGURATION');
  const server = net.createServer(client => {
    client.pause();
    let upstream;
    try {
      upstream = tls.connect({ host: upstreamHost, port: upstreamPort, ca,
        servername: SERVER_NAME, rejectUnauthorized: true, minVersion: 'TLSv1.2' });
    } catch { client.destroy(); return; }
    const close = () => { clearTimeout(handshakeTimer); client.destroy(); upstream.destroy(); };
    const handshakeTimer = setTimeout(close, 5000);
    client.on('error', close);
    upstream.on('error', close);
    client.on('close', close);
    upstream.on('close', close);
    client.setTimeout(120000, close);
    upstream.once('secureConnect', () => {
      if (!upstream.authorized) { close(); return; }
      clearTimeout(handshakeTimer);
      upstream.setTimeout(120000, close);
      client.pipe(upstream).pipe(client);
      client.resume();
    });
  });
  server.maxConnections = 4;
  return server;
}

export function readPinnedCa(expectedHash) {
  if (!/^[a-f0-9]{64}$/.test(expectedHash)) throw Error('H454_CA_HASH');
  const dir = fs.lstatSync('/opt/hermes-rollback');
  if (!dir.isDirectory() || dir.isSymbolicLink() || dir.uid !== 0 || dir.gid !== 0 ||
      (dir.mode & 0o777) !== 0o755) throw Error('H454_CA_DIRECTORY');
  const fd = fs.openSync(CA_PATH, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const info = fs.fstatSync(fd);
    if (!info.isFile() || info.uid !== 0 || info.gid !== 0 || info.nlink !== 1 ||
        (info.mode & 0o777) !== 0o444 || info.size < 1 || info.size > 65536) throw Error('H454_CA_FILE');
    const ca = fs.readFileSync(fd);
    if (createHash('sha256').update(ca).digest('hex') !== expectedHash) throw Error('H454_CA_DRIFT');
    return ca;
  } finally { fs.closeSync(fd); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 5 || !privateIPv4(process.argv[2])) throw Error('H454_PROXY_ARGUMENTS');
    const network = isolatedNetwork(process.argv[4]);
    const listenHost = isolatedIPv4(os.networkInterfaces(), process.argv[4]);
    if (((ipv4Number(process.argv[2]) & network.mask) >>> 0) === network.base) throw Error('H454_PROXY_ROUTE');
    const ca = readPinnedCa(process.argv[3]);
    const server = createRollbackProxy({ upstreamHost: process.argv[2], upstreamPort: 38184, ca });
    server.on('error', () => { console.error('H454_ROLLBACK_PROXY_ERROR'); process.exitCode = 1; });
    server.listen(38180, listenHost, () => console.log('H454_ROLLBACK_PROXY_READY'));
  } catch {
    console.error('H454_ROLLBACK_PROXY_REFUSED');
    process.exitCode = 1;
  }
}
