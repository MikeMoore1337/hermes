#!/usr/bin/env node
// CI-only: two throwaway device tokens in a disposable relay SQLite store.
// Never execute on owner VPS; stdout is only read into a masked CI variable.
import { pathToFileURL } from 'node:url';
const { SqliteStore } = await import(pathToFileURL('/opt/brc/packages/relay/dist/store/sqlite.js').href);
const store = new SqliteStore(process.env.BRC_DB ?? '/state/relay.sqlite');
try {
  const owner = store.getUserByName(process.env.BRC_ADMIN_USER ?? 'ci-owner');
  if (!owner) throw Error('NO_CI_OWNER_IN_EPHEMERAL_DB');
  const one = store.issueDeviceToken('ci-native-one', owner.id, 'ci-native-one', 'linux');
  const two = store.issueDeviceToken('ci-native-two', owner.id, 'ci-native-two', 'linux');
  process.stdout.write(JSON.stringify({ one, two }));
} finally {
  store.close();
}
