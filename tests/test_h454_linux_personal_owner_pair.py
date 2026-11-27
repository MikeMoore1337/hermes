"""Owner pairing mutates only one exact, still-pending synthetic code."""
import os
import sqlite3
import unittest

if os.name != 'nt':
    from scripts import h454_linux_personal_owner_pair as operator

NOW = 1_700_000_000_000
CODE = 'ABCD-2345'
HEX = 'a' * 32


@unittest.skipIf(os.name == 'nt', 'owner operator runs on Linux')
class LinuxPersonalOwnerTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:', isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
          CREATE TABLE users(id TEXT, username TEXT);
          CREATE TABLE devices(device_id TEXT, user_id TEXT, name TEXT, token_hash TEXT);
          CREATE TABLE device_codes(device_code TEXT, user_code TEXT, client_name TEXT,
            user_id TEXT, approved INTEGER, denied INTEGER, device_id TEXT,
            expires_at INTEGER, created_at INTEGER);
        ''')
        self.db.execute('INSERT INTO users VALUES (?,?)', ('owner', 'admin'))
        self.db.execute('INSERT INTO devices VALUES (?,?,?,?)',
                        ('h454-linux-yfc-' + 'b' * 32, 'owner', 'H454 YFC VPS native read-only', 'hash'))

    def add_code(self, target):
        self.db.execute('INSERT INTO device_codes VALUES (?,?,?,?,?,?,?,?,?)',
            ('synthetic-device-code', CODE, operator.NAMES[target], None, 0, 0, None, NOW + 180_000, NOW))

    def test_each_host_binds_one_pending_code_without_touching_read_only_device(self):
        for target in ('hermes-vps', 'yfc-vps'):
            with self.subTest(target=target):
                self.add_code(target)
                before = [tuple(row) for row in self.db.execute('SELECT * FROM devices')]
                row = operator.pending(self.db, target, CODE, NOW + 1)
                device = operator.approve(self.db, target=target, user_code=CODE,
                                          original=row, new_hex=HEX, now_ms=NOW + 1)
                self.assertEqual(device, operator.PREFIX[target] + HEX)
                self.assertEqual(tuple(self.db.execute(
                    'SELECT approved,user_id,device_id FROM device_codes').fetchone()), (1, 'owner', device))
                self.assertEqual([tuple(row) for row in self.db.execute('SELECT * FROM devices')], before)
                with self.assertRaises(operator.PairDenied):
                    operator.approve(self.db, target=target, user_code=CODE,
                                     original=row, new_hex=HEX, now_ms=NOW + 1)
                self.db.execute('DELETE FROM device_codes')

    def test_cross_host_changed_expired_and_existing_identity_are_rejected(self):
        self.add_code('yfc-vps')
        row = operator.pending(self.db, 'yfc-vps', CODE, NOW + 1)
        with self.assertRaises(operator.PairDenied):
            operator.pending(self.db, 'hermes-vps', CODE, NOW + 1)
        self.db.execute('UPDATE device_codes SET expires_at=?', (NOW + 180_001,))
        with self.assertRaises(operator.PairDenied):
            operator.approve(self.db, target='yfc-vps', user_code=CODE,
                             original=row, new_hex=HEX, now_ms=NOW + 1)
        self.db.execute('UPDATE device_codes SET expires_at=?', (NOW + 1_000,))
        with self.assertRaises(operator.PairDenied):
            operator.pending(self.db, 'yfc-vps', CODE, NOW + 1)
        self.db.execute('UPDATE device_codes SET expires_at=?', (NOW + 180_000,))
        self.db.execute('INSERT INTO devices VALUES (?,?,?,?)',
                        (operator.PREFIX['yfc-vps'] + HEX, 'owner', operator.NAMES['yfc-vps'], 'hash'))
        with self.assertRaises(operator.PairDenied):
            operator.approve(self.db, target='yfc-vps', user_code=CODE,
                             original=row, new_hex=HEX, now_ms=NOW + 1)


if __name__ == '__main__':
    unittest.main()
