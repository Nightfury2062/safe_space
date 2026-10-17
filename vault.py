"""
vault.py - SafeSpace storage layer (the "house" around the lockers).

Layer 1 (house):
  master password -> Argon2id(salt_m) -> MK -> HKDF("smk-enc") -> SMK_enc
  SMK_enc unwraps VK (vault key). A random recovery key wraps a second copy of VK.
  VK -> HKDF("index") encrypts the index (names, usernames, categories, strength).
Layer 2 (lockers): exactly the scheme in open_locker_demo.py, one locker per entry.
  An entry without an "extra PIN" uses the empty string as its PIN.

Everything on disk is AEAD-sealed (XChaCha20-Poly1305) except salts and KDF costs.
"""

import base64
import csv
import hashlib
import hmac
import json
import os
import secrets
import time

from nacl.exceptions import CryptoError

from open_locker_demo import (
    KEY_LEN, PIN_KDF, SALT_LEN, WrongPinOrTampered,
    argon2id, create_locker, hkdf, open_locker, open_sealed, seal, wipe,
)

FORMAT = "safespace-1"
MASTER_KDF = dict(PIN_KDF)


class WrongMasterPassword(Exception):
    """Wrong master password / recovery key, or the vault file was modified."""


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def _master_wrap_key(password: str, salt: bytes, kdf: dict) -> bytes:
    mk = argon2id(password.encode("utf-8"), salt, kdf["m_kib"], kdf["t"], kdf["p"])
    return hkdf(mk, b"smk-enc")


def _recovery_wrap_key(recovery_key: str, salt: bytes) -> bytes:
    raw = base64.b32decode(normalize_recovery_key(recovery_key))
    return hkdf(raw, b"recovery", salt=salt)


def normalize_recovery_key(text: str) -> str:
    return "".join(ch for ch in text.upper() if ch.isalnum())


def new_recovery_key() -> str:
    """160 random bits shown as 8 groups of 4 base32 characters."""
    s = base64.b32encode(secrets.token_bytes(20)).decode("ascii")
    return "-".join(s[i:i + 4] for i in range(0, len(s), 4))


def default_vault_path() -> str:
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, "SafeSpace", "vault.json")


class Vault:
    """An unlocked vault. Construct with Vault.create() or Vault.unlock()."""

    def __init__(self, path: str, data: dict, vault_key: bytes):
        self.path = path
        self._data = data
        self._vault_id = _unb64(data["vault_id"])
        self._vk = bytearray(vault_key)
        self.items = self._load_index()          # {locker_id_hex: metadata dict}

    # ------------------------------------------------------------ lifecycle
    @staticmethod
    def exists(path: str) -> bool:
        return os.path.exists(path)

    @classmethod
    def create(cls, path: str, master_password: str) -> tuple["Vault", str]:
        """Make a new vault. Returns (vault, recovery_key); show the key to the user once."""
        vault_id = secrets.token_bytes(16)
        vk = secrets.token_bytes(KEY_LEN)
        data = {"format": FORMAT, "vault_id": _b64(vault_id), "settings": {"autolock_min": 5},
                "lockers": {}}
        data["index"] = _b64(seal(hkdf(vk, b"index"), b"{}", b"index" + vault_id))
        v = cls(path, data, vk)
        v._set_master(master_password)
        recovery = v.reset_recovery_key(save=False)
        v.save()
        return v, recovery

    @classmethod
    def _read(cls, path: str) -> dict:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("format") != FORMAT:
            raise ValueError("Not a SafeSpace vault file")
        return data

    @classmethod
    def unlock(cls, path: str, master_password: str) -> "Vault":
        data = cls._read(path)
        m = data["master"]
        key = _master_wrap_key(master_password, _unb64(m["salt"]), m["kdf"])
        try:
            vk = open_sealed(key, _unb64(m["wrapped_vk"]), b"master" + _unb64(data["vault_id"]))
        except CryptoError:
            raise WrongMasterPassword() from None
        return cls(path, data, vk)

    @classmethod
    def unlock_with_recovery(cls, path: str, recovery_key: str) -> "Vault":
        data = cls._read(path)
        r = data["recovery"]
        try:
            key = _recovery_wrap_key(recovery_key, _unb64(r["salt"]))
            vk = open_sealed(key, _unb64(r["wrapped_vk"]), b"recovery" + _unb64(data["vault_id"]))
        except (CryptoError, ValueError):
            raise WrongMasterPassword() from None
        return cls(path, data, vk)

    def lock(self) -> None:
        wipe(self._vk)
        self.items = {}

    def save(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=1)
        os.replace(tmp, self.path)           # atomic: never leave a half-written vault

    # ------------------------------------------------------------ house keys
    def _set_master(self, master_password: str) -> None:
        salt = secrets.token_bytes(SALT_LEN)
        key = _master_wrap_key(master_password, salt, MASTER_KDF)
        self._data["master"] = {"salt": _b64(salt), "kdf": dict(MASTER_KDF),
                                "wrapped_vk": _b64(seal(key, bytes(self._vk), b"master" + self._vault_id))}

    def change_master_password(self, new_password: str) -> None:
        """Only re-wraps VK; lockers and index are untouched."""
        self._set_master(new_password)
        self.save()

    def reset_recovery_key(self, save: bool = True) -> str:
        """Replace the recovery key. The old one stops working immediately."""
        rk = new_recovery_key()
        salt = secrets.token_bytes(SALT_LEN)
        key = _recovery_wrap_key(rk, salt)
        self._data["recovery"] = {"salt": _b64(salt), "created": int(time.time()),
                                  "wrapped_vk": _b64(seal(key, bytes(self._vk), b"recovery" + self._vault_id))}
        if save:
            self.save()
        return rk

    @property
    def recovery_created(self) -> int:
        return self._data.get("recovery", {}).get("created", 0)

    # ------------------------------------------------------------ settings
    @property
    def settings(self) -> dict:
        return self._data.setdefault("settings", {"autolock_min": 5})

    def set_setting(self, key: str, value) -> None:
        self.settings[key] = value
        self.save()

    # ------------------------------------------------------------ index
    def _index_key(self) -> bytes:
        return hkdf(bytes(self._vk), b"index")

    def _load_index(self) -> dict:
        try:
            raw = open_sealed(self._index_key(), _unb64(self._data["index"]), b"index" + self._vault_id)
        except CryptoError:
            raise WrongMasterPassword("Vault index failed authentication") from None
        return json.loads(raw)

    def _save_index(self) -> None:
        raw = json.dumps(self.items).encode("utf-8")
        self._data["index"] = _b64(seal(self._index_key(), raw, b"index" + self._vault_id))
        self.save()

    # ------------------------------------------------------------ entries
    def add_item(self, meta: dict, secret: dict, pin: str = "") -> str:
        """meta: name, url, username, category, strength. secret: password, notes."""
        rec = create_locker(bytes(self._vk), self._vault_id, meta["name"], secret, pin)
        lid = rec["locker_id"].hex()
        self._data["lockers"][lid] = {"salt": _b64(rec["salt"]), "kdf": rec["kdf"],
                                      "wrapped_item_key": _b64(rec["wrapped_item_key"]),
                                      "secret_blob": _b64(rec["secret_blob"])}
        now = int(time.time())
        self.items[lid] = dict(meta, has_pin=bool(pin), created=now, updated=now)
        self._save_index()
        return lid

    def update_item(self, lid: str, meta: dict, secret: dict, pin: str = "") -> str:
        """Re-seals the entry under a fresh locker; keeps the original creation time."""
        created = self.items[lid].get("created", int(time.time()))
        self._data["lockers"].pop(lid, None)
        self.items.pop(lid, None)
        new_lid = self.add_item(meta, secret, pin)
        self.items[new_lid]["created"] = created
        self._save_index()
        return new_lid

    def delete_item(self, lid: str) -> None:
        self._data["lockers"].pop(lid, None)
        self.items.pop(lid, None)
        self._save_index()

    def reveal(self, lid: str, pin: str = "") -> dict:
        """Opens the locker. Raises WrongPinOrTampered."""
        rec = self._data["lockers"][lid]
        record = {"locker_id": bytes.fromhex(lid), "account": self.items[lid]["name"],
                  "salt": _unb64(rec["salt"]), "kdf": rec["kdf"],
                  "wrapped_item_key": _unb64(rec["wrapped_item_key"]),
                  "secret_blob": _unb64(rec["secret_blob"])}
        return open_locker(bytes(self._vk), self._vault_id, record, pin, verbose=False)

    def fingerprint(self, password: str) -> str:
        """Keyed hash used only to spot reused passwords; meaningless without VK."""
        key = hkdf(bytes(self._vk), b"reuse-fp")
        return hmac.new(key, password.encode("utf-8"), hashlib.sha256).hexdigest()[:32]

    def reused_ids(self) -> set:
        seen = {}
        for lid, m in self.items.items():
            seen.setdefault(m.get("fp"), []).append(lid)
        return {lid for fp, ids in seen.items() if fp and len(ids) > 1 for lid in ids}

    # ------------------------------------------------------------ import / export
    def export_backup(self, dest: str) -> None:
        """Encrypted copy: still needs the master password (or recovery key) to open."""
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=1)

    def delete_vault_file(self) -> None:
        self.lock()
        if os.path.exists(self.path):
            os.remove(self.path)

    def export_csv(self, dest: str) -> tuple[int, int]:
        """UNENCRYPTED export (name,url,username,password,notes,category).
        Entries with an extra PIN are skipped. Returns (exported, skipped)."""
        done = skipped = 0
        with open(dest, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["name", "url", "username", "password", "notes", "category"])
            for lid, m in sorted(self.items.items(), key=lambda kv: kv[1]["name"].lower()):
                if m.get("has_pin"):
                    skipped += 1
                    continue
                s = self.reveal(lid)
                w.writerow([m["name"], m.get("url", ""), m.get("username", ""),
                            s.get("password", ""), s.get("notes", ""), m.get("category", "")])
                done += 1
        return done, skipped


def read_import_csv(src: str) -> list[dict]:
    """Reads a CSV from SafeSpace, Chrome, Edge, Firefox, Bitwarden or 1Password-style
    exports. Returns rows with name, url, username, password, notes, category."""
    aliases = {
        "name": ("name", "title", "account", "site"),
        "url": ("url", "login_uri", "website", "web site", "origin", "hostname"),
        "username": ("username", "login_username", "user", "email", "login"),
        "password": ("password", "login_password", "pass"),
        "notes": ("notes", "note", "extra", "comments"),
        "category": ("category", "folder", "group", "type"),
    }
    rows = []
    with open(src, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        cols = {c.strip().lower(): c for c in (reader.fieldnames or [])}
        pick = {k: next((cols[a] for a in al if a in cols), None) for k, al in aliases.items()}
        if not pick["password"]:
            raise ValueError("No 'password' column found in this file.")
        for r in reader:
            row = {k: (r.get(c) or "").strip() if c else "" for k, c in pick.items()}
            if not row["password"]:
                continue
            if not row["name"]:
                row["name"] = row["url"].split("//")[-1].split("/")[0] or row["username"] or "Imported"
            rows.append(row)
    return rows
