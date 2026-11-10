#!/usr/bin/env node
// Actual pinned BRC Express /device/poll test against disposable SQLite.
// NEVER production/owner device pairing, and no non-loopback connections.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';

const root = process.cwd();
const { buildRelay } = await import(pathToFileURL(
  path.join(root, 'packages/relay/dist/app.js')).href);
const secret = () => randomBytes(32).toString('hex');
const temp = mkdtempSync(path.join(tmpdir(), 'h454-pairing-e2e-'));
const relay = buildRelay({
  port: 0, host: '127.0.0.1',
  publicUrl: 'http://127.0.0.1',
  trustProxy: false, dbFile: path.join(temp, 'relay.sqlite'),
  sessionSecret: secret(), adminUser: 'unit-only',
  adminPassword: secret(), relayVersion: 'pinned-fixture',
}, () => {});

async function attempt(port, device_code, profile, extra) {
  const body = {
    device_code,
    name: profile.name,
    platform: profile.platform,
    ...extra,
  };
  const result = await fetch('http://127.0.0.1:' + port + '/device/poll', {
    method: 'POST', headers: {'content-type':'application/json'},
    body: JSON.stringify(body),
  });
  return {status:result.status,body:await result.json()};
}

const PROFILES = [
  {name:'H454 Windows native read-only', platform:'win32', id:'h454-win-native-'+ 'a'.repeat(32)},
  {name:'H454 Hermes VPS native read-only', platform:'linux', id:'h454-linux-hermes-'+ 'b'.repeat(32)},
  {name:'H454 YFC VPS native read-only', platform:'linux', id:'h454-linux-yfc-'+ 'c'.repeat(32)},
];

try {
  await new Promise((resolve, reject) => {
    relay.http.once('error', reject);
    relay.http.listen(0, '127.0.0.1', resolve);
  });
  const address = relay.http.address();
  if (!address || typeof address === 'string') throw Error('NO_LOOPBACK_PORT');
  const owner = relay.store.getUserByName('unit-only');
  if (!owner) throw Error('NO_SYNTHETIC_OWNER');
  for (const profile of PROFILES) {
    const pending = relay.store.createDeviceCode(profile.name, 60000);
    relay.store.approveDeviceCode(pending.device_code, owner.id, profile.id);
    for (const extras of [
      {device_id:'another-owner-controlled-device'},
      {device_id:profile.id},
      {name:'untrusted-agent'},
      {platform:'linux/docker'},
    ]) {
      const reply = await attempt(address.port,pending.device_code,profile,extras);
      if (reply.status !== 403 || reply.body.error !== 'native_pairing_scope_denied') {
        throw Error('NATIVE_PAIR_REJECTED_OVERRIDE_NOT_DENIED');
      }
      if (relay.store.getDevice(profile.id)) throw Error('DENIAL_MINTED_TOKEN');
    }
    const paired = await attempt(address.port,pending.device_code,profile,{});
    if (paired.status !== 200 || paired.body.device_id !== profile.id
        || paired.body.token_type !== 'bearer'
        || !paired.body.device_token?.startsWith('brc_dev_')) {
      throw Error('OWNER_BOUND_NATIVE_PAIRING_DENIED');
    }
    const stored = relay.store.getDevice(profile.id);
    if (!stored || stored.user_id !== owner.id || stored.name !== profile.name
        || stored.platform !== profile.platform) {
      throw Error('OWNER_NATIVE_RECORD_MISMATCH');
    }
    const replay = await attempt(address.port,pending.device_code,profile,{});
    if (replay.status === 200) throw Error('PAIRING_CODE_REPLAY_ACCEPTED');
    const second = relay.store.createDeviceCode(profile.name,60000);
    relay.store.approveDeviceCode(second.device_code,owner.id,profile.id);
    const overwrite = await attempt(address.port,second.device_code,profile,{});
    if (overwrite.status !== 403) throw Error('REPAIR_WITHOUT_NEW_APPROVAL');
  }
  for (const native of [
    {name:'H454 Windows native read-only',platform:'win32',id:'h454-win-native-'+ 'd'.repeat(32)},
  ]) {
    // Generic BRC approvals are insufficient: require an owner-selected
    // H454 native ID in the pending row.
    const code=relay.store.createDeviceCode(native.name,60000);
    relay.store.approveDeviceCode(code.device_code,owner.id,'');
    const forged=await attempt(address.port,code.device_code,native,
                              {device_id:native.id});
    if (forged.status!==403) throw Error('UNBOUND_NATIVE_CLAIM_ACCEPTED');
  }
  console.log('H454_NATIVE_OWNER_BOUND_BRC_PAIRING=PASS');
  console.log('H454_EXISTING_BRC_OAUTH=UNCHANGED');
  console.log('H454_OWNER_HOST_DEVICE_PAIRING=NOT_RUN');
} finally {
  await relay.close();
  rmSync(temp, {recursive:true,force:true});
}
