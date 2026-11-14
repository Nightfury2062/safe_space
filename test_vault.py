"""Run: python -m unittest test_vault -v"""

import csv
import json
import os
import tempfile
import unittest

import passgen
from open_locker_demo import WrongPinOrTampered
from vault import Vault, WrongMasterPassword, read_import_csv

MASTER = "correct horse battery staple"


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def dump(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def meta(v, name, pw, **kw):
    return dict({"name": name, "url": "", "username": "u", "category": "Other",
                 "strength": passgen.strength(pw)[0], "fp": v.fingerprint(pw)}, **kw)


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "vault.json")
        self.v, self.rk = Vault.create(self.path, MASTER)

    def tearDown(self):
        self.dir.cleanup()

    def test_unlock_and_wrong_master(self):
        lid = self.v.add_item(meta(self.v, "Gmail", "pw1-Long-enough!"), {"password": "pw1-Long-enough!"})
        v2 = Vault.unlock(self.path, MASTER)
        self.assertEqual(v2.items[lid]["name"], "Gmail")
        self.assertEqual(v2.reveal(lid)["password"], "pw1-Long-enough!")
        with self.assertRaises(WrongMasterPassword):
            Vault.unlock(self.path, "nope")

    def test_names_not_in_plaintext_file(self):
        self.v.add_item(meta(self.v, "SecretBankName", "x"), {"password": "hunter2"})
        with open(self.path, encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn("SecretBankName", raw)
        self.assertNotIn("hunter2", raw)

    def test_pin_locker(self):
        lid = self.v.add_item(meta(self.v, "Bank", "p"), {"password": "p"}, pin="4821")
        self.assertTrue(self.v.items[lid]["has_pin"])
        self.assertEqual(self.v.reveal(lid, "4821")["password"], "p")
        with self.assertRaises(WrongPinOrTampered):
            self.v.reveal(lid, "0000")
        with self.assertRaises(WrongPinOrTampered):
            self.v.reveal(lid, "")

    def test_change_master_and_recovery(self):
        lid = self.v.add_item(meta(self.v, "A", "p"), {"password": "p"})
        self.v.change_master_password("new master password 42")
        with self.assertRaises(WrongMasterPassword):
            Vault.unlock(self.path, MASTER)
        v2 = Vault.unlock_with_recovery(self.path, self.rk.lower().replace("-", " "))
        self.assertEqual(v2.reveal(lid)["password"], "p")
        new_rk = v2.reset_recovery_key()
        with self.assertRaises(WrongMasterPassword):
            Vault.unlock_with_recovery(self.path, self.rk)
        Vault.unlock_with_recovery(self.path, new_rk)
        with self.assertRaises(WrongMasterPassword):
            Vault.unlock_with_recovery(self.path, "not-a-key")

    def test_update_delete_and_reuse(self):
        a = self.v.add_item(meta(self.v, "A", "same"), {"password": "same"})
        b = self.v.add_item(meta(self.v, "B", "same"), {"password": "same"})
        self.assertEqual(self.v.reused_ids(), {a, b})
        b2 = self.v.update_item(b, meta(self.v, "B", "different"), {"password": "different"})
        self.assertNotIn(b, self.v.items)
        self.assertEqual(self.v.reused_ids(), set())
        self.v.delete_item(a)
        self.assertEqual(list(Vault.unlock(self.path, MASTER).items), [b2])

    def test_tampered_index_or_swapped_lockers(self):
        a = self.v.add_item(meta(self.v, "A", "pa"), {"password": "pa"})
        b = self.v.add_item(meta(self.v, "B", "pb"), {"password": "pb"})
        data = load(self.path)
        data["lockers"][a], data["lockers"][b] = data["lockers"][b], data["lockers"][a]
        dump(self.path, data)
        v2 = Vault.unlock(self.path, MASTER)
        with self.assertRaises(WrongPinOrTampered):
            v2.reveal(a)
        data["index"] = data["index"][:-4] + "AAA="
        dump(self.path, data)
        with self.assertRaises(WrongMasterPassword):
            Vault.unlock(self.path, MASTER)

    def test_csv_roundtrip_skips_pin_items(self):
        self.v.add_item(meta(self.v, "A", "pa", url="a.com"), {"password": "pa", "notes": "n"})
        self.v.add_item(meta(self.v, "B", "pb"), {"password": "pb"}, pin="1111")
        out = os.path.join(self.dir.name, "out.csv")
        self.assertEqual(self.v.export_csv(out), (1, 1))
        rows = read_import_csv(out)
        self.assertEqual(rows[0]["password"], "pa")
        self.assertEqual(rows[0]["url"], "a.com")

    def test_import_browser_style_csv(self):
        src = os.path.join(self.dir.name, "chrome.csv")
        with open(src, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["name", "url", "username", "password", "note"])
            w.writerow(["", "https://example.com/login", "me", "s3cret", ""])
            w.writerow(["empty", "https://x.com", "me", "", ""])
        rows = read_import_csv(src)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "example.com")

    def test_passgen(self):
        pw = passgen.generate_password(20, symbols=False)
        self.assertEqual(len(pw), 20)
        self.assertTrue(pw.isalnum())
        self.assertGreaterEqual(passgen.strength(passgen.generate_password())[0], 3)
        self.assertTrue(passgen.is_weak(passgen.strength("Summer2024!")[0]))

    def test_biometric_unlock(self):
        self.assertFalse(self.v.has_biometric)
        self.assertFalse(Vault.is_biometric_enabled(self.path))
        bio_key = os.urandom(32)
        self.v.enable_biometric(bio_key)
        self.assertTrue(self.v.has_biometric)
        self.assertTrue(Vault.is_biometric_enabled(self.path))

        # Unlock with correct biometric key
        v2 = Vault.unlock_with_biometric(self.path, bio_key)
        self.assertEqual(len(v2.items), len(self.v.items))

        # Unlock with wrong biometric key
        with self.assertRaises(WrongMasterPassword):
            Vault.unlock_with_biometric(self.path, os.urandom(32))

        # Disable biometric
        v2.disable_biometric()
        self.assertFalse(v2.has_biometric)
        self.assertFalse(Vault.is_biometric_enabled(self.path))



if __name__ == "__main__":
    unittest.main()
