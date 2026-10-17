"""
open_locker_demo.py - Step-by-step walkthrough of opening ONE locker with its PIN.

House Vault design (Bitwarden + KeePassXC primitives):
  Master password -> Argon2id -> MK -> HKDF -> SMK_enc -> unwrap VK (vault key)
  VK -> HKDF("locker"||id) -> K_lockbase_i
  PIN -> Argon2id(salt_i) -> P_i
  KEK_i = HKDF(K_lockbase_i || P_i, salt_i, "kek"||id)
  KEK_i unwraps IK_i (item key); IK_i decrypts the secret blob.

Requires: pip install argon2-cffi pynacl cryptography
"""

import json
import os
import secrets
import time

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt as _aead_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt as _aead_encrypt,
)
from nacl.exceptions import CryptoError

# ---------------------------------------------------------------- parameters
NONCE_LEN = 24          # XChaCha20 nonce: 192 bits, safe to pick at random
KEY_LEN = 32            # 256-bit keys everywhere
SALT_LEN = 16           # 128-bit salts

# PIN KDF cost. Tune so one guess takes ~0.5-1 s on your machine.
PIN_KDF = {"m_kib": 131072, "t": 3, "p": 1}   # 128 MiB, 3 passes


class WrongPinOrTampered(Exception):
    """Raised when the PIN is wrong OR the locker data was modified.
    We deliberately do not say which, so an attacker learns nothing."""


# ---------------------------------------------------------------- primitives
def argon2id(secret: bytes, salt: bytes, m_kib: int, t: int, p: int) -> bytes:
    return hash_secret_raw(secret, salt, t, m_kib, p, KEY_LEN, Type.ID)


def hkdf(ikm: bytes, info: bytes, salt: bytes | None = None) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, info=info).derive(ikm)


def seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_LEN)
    return nonce + _aead_encrypt(plaintext, aad, nonce, key)


def open_sealed(key: bytes, blob: bytes, aad: bytes) -> bytes:
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return _aead_decrypt(ct, aad, nonce, key)       # raises CryptoError on failure


def wipe(buf: bytearray) -> None:
    """Best-effort overwrite. Python may keep other copies; see report notes."""
    for i in range(len(buf)):
        buf[i] = 0


# ---------------------------------------------------------------- key derivation for a locker
def derive_kek(vault_key: bytes, locker_id: bytes, pin: str, salt: bytes, kdf: dict) -> bytearray:
    """KEK_i = HKDF( K_lockbase_i || P_i , salt_i , "kek"||locker_id )"""
    k_lockbase = hkdf(vault_key, b"locker" + locker_id)                      # from the house
    p_i = argon2id(pin.encode("utf-8"), salt, kdf["m_kib"], kdf["t"], kdf["p"])  # from the PIN
    kek = hkdf(k_lockbase + p_i, b"kek" + locker_id, salt=salt)              # needs BOTH
    return bytearray(kek)


# ---------------------------------------------------------------- create (so we have something to open)
def create_locker(vault_key: bytes, vault_id: bytes, account: str, secret: dict, pin: str) -> dict:
    locker_id = secrets.token_bytes(16)
    salt = secrets.token_bytes(SALT_LEN)
    kek = derive_kek(vault_key, locker_id, pin, salt, PIN_KDF)
    item_key = bytearray(secrets.token_bytes(KEY_LEN))

    aad_wrap = vault_id + locker_id
    aad_data = vault_id + locker_id + account.encode("utf-8")

    record = {
        "locker_id": locker_id,
        "account": account,                     # lives in the encrypted index in the real file
        "salt": salt,
        "kdf": dict(PIN_KDF),
        "wrapped_item_key": seal(bytes(kek), bytes(item_key), aad_wrap),
        "secret_blob": seal(bytes(item_key), json.dumps(secret).encode("utf-8"), aad_data),
    }
    wipe(kek)
    wipe(item_key)
    return record


# ---------------------------------------------------------------- OPEN: the walkthrough
def open_locker(vault_key: bytes, vault_id: bytes, record: dict, pin: str, verbose: bool = True) -> dict:
    log = print if verbose else (lambda *a, **k: None)
    locker_id, salt, account = record["locker_id"], record["salt"], record["account"]

    # Step 1: read the locker's public parameters from the file
    log(f"[1] Locker '{account}': salt={salt.hex()[:16]}..., kdf={record['kdf']}")

    # Step 2: derive this locker's share of the house key
    # Step 3: stretch the PIN with Argon2id (the slow, deliberate step)
    # Step 4: combine both with HKDF into the key-encryption key
    t0 = time.perf_counter()
    kek = derive_kek(vault_key, locker_id, pin, salt, record["kdf"])
    log(f"[2-4] KEK derived from vault key + PIN in {time.perf_counter() - t0:.2f} s")

    item_key = bytearray()
    try:
        # Step 5: unwrap the item key. AEAD tag check = PIN check.
        item_key = bytearray(open_sealed(bytes(kek), record["wrapped_item_key"], vault_id + locker_id))
        log("[5] Item key unwrapped (Poly1305 tag verified -> PIN correct)")

        # Step 6: decrypt the secret. Account name is bound as associated data.
        aad = vault_id + locker_id + account.encode("utf-8")
        secret = json.loads(open_sealed(bytes(item_key), record["secret_blob"], aad))
        log("[6] Secret decrypted and authenticated")
        return secret
    except CryptoError:
        raise WrongPinOrTampered("Wrong PIN, or locker data was modified") from None
    finally:
        # Step 7: wipe keys immediately; the caller wipes the secret after use
        wipe(kek)
        wipe(item_key)
        log("[7] KEK and item key wiped from memory")


# ---------------------------------------------------------------- demo
if __name__ == "__main__":
    # Pretend layer 1 already happened: the house is unlocked and we hold VK.
    vault_id = secrets.token_bytes(16)
    vault_key = secrets.token_bytes(KEY_LEN)

    print("=== Creating a locker for 'Gmail' with PIN 482915 ===")
    rec = create_locker(vault_key, vault_id, "Gmail",
                        {"username": "me@example.com", "password": "c0rrect-H0rse!"}, "482915")

    print("\n=== Opening with the CORRECT PIN ===")
    s = open_locker(vault_key, vault_id, rec, "482915")
    print(f"    -> password = {s['password']}")

    print("\n=== Opening with a WRONG PIN ===")
    try:
        open_locker(vault_key, vault_id, rec, "000000")
    except WrongPinOrTampered as e:
        print(f"    -> rejected: {e}")

    print("\n=== Tamper test: attacker renames the account to 'Bank' ===")
    forged = dict(rec, account="Bank")
    try:
        open_locker(vault_key, vault_id, forged, "482915", verbose=False)
    except WrongPinOrTampered as e:
        print(f"    -> rejected: {e}")

    print("\n=== Tamper test: one bit flipped in the secret blob ===")
    blob = bytearray(rec["secret_blob"]); blob[-1] ^= 1
    try:
        open_locker(vault_key, vault_id, dict(rec, secret_blob=bytes(blob)), "482915", verbose=False)
    except WrongPinOrTampered as e:
        print(f"    -> rejected: {e}")

    print("\n=== Correct PIN but WRONG vault key (house not truly unlocked) ===")
    try:
        open_locker(secrets.token_bytes(KEY_LEN), vault_id, rec, "482915", verbose=False)
    except WrongPinOrTampered as e:
        print(f"    -> rejected: {e}")
