# SafeSpace — desktop password manager prototype

> **Course prototype** for the Usable Security course at IIIT Delhi. It has not had an independent
> security review. Use the demo mode for testing and **do not store real passwords** in it.

Prototype for the SafeSpace usability study (see `../Usability Study Interview Guide.pdf`).

## Quick start (Windows)

1. Install Python 3.10+ from python.org (tick "Add Python to PATH").
2. In this folder, run once: `pip install -r requirements.txt`
3. Double-click **`SafeSpace Demo.bat`** for study sessions, or **`SafeSpace.bat`** for a personal vault.

## Run from a terminal

```
pip install -r requirements.txt
python app.py --demo     # fresh sample vault for a study session (resets every launch)
python app.py            # your own vault, stored in %APPDATA%\SafeSpace\vault.json
python -m unittest test_vault -v
```

Demo vault: master password `SafeSpace demo 2026`; the HDFC entry has an extra PIN `246810` (Extra-lock PINs must be at least 6 digits).
It holds 11 logins, 4 of them weak, so the warning banner shows up for Task 5.
The two Instagram logins appear under one "instagram.com" group in the list.

## Where each study task lives

| Study task | In the app |
|---|---|
| Home-screen first impression | Header: search, **+ Add login**, **PassGen**, **Import**, **Export**, **⚙ Account**; yellow warning banner; categories sidebar |
| 1. Add a credential | **+ Add login** → name / website / username / password / category / notes |
| 2. Generate a strong password | **PassGen** button (standalone, then "Save as new login…") or **Generate…** inside the add/edit form ("Use this password") |
| 3. Find a password | Search box (name, website, username) and category sidebar; logins on the same website are grouped |
| 4. Edit an entry | Select a login → **✎ Edit** in the details panel (also **⋯** menu, double-click or right-click a row) |
| 5. Weak-password warning | Banner → **Review them** → "Needs attention" list → **Update password…** |
| 6. Security / account | **⚙ Account**: how the vault is protected, change master password, recovery key, auto-lock, clipboard clearing, light/dark appearance, text size (Normal / Large / Extra large), delete account |

## Security design

Builds on `open_locker_demo.py` (the "house and lockers" design):

* **House:** master password → Argon2id → HKDF → key that unwraps the vault key (VK).
  A random recovery key (shown once at setup) wraps a second copy of VK.
* **Biometrics (Face ID & Active Liveness):** Enrolling Face ID generates a random 256-bit Biometric Key (BK) that wraps VK.
  BK and the user's ArcFace reference embedding are encrypted on disk with Windows DPAPI (tied to the OS user).
  During unlock, RetinaFace detects the face, ArcFace extracts the 512-d normalized embedding, and once identity is confirmed
  (Cosine Similarity $\ge \tau = 0.62$), an **Active Liveness Challenge** requires a 3D head turn (measured via facial landmark yaw ratio).
  This prevents presentation attacks using 2D printed photos or smartphone screens.
  To eliminate latency, ONNX models are pre-warmed in a background thread and the camera uses DirectShow for sub-second startup.
* **Index:** names, usernames, websites, categories and strength scores are sealed under a key derived from VK. The file on disk shows no account names.
* **Lockers:** each login is its own locker (`create_locker` / `open_locker`, unchanged).
  The optional "Extra lock" PIN is the locker PIN; without one the PIN is the empty string.
* All ciphertext is XChaCha20-Poly1305 with IDs bound as associated data, so swapping or editing entries is detected.
* Reused passwords are found with a keyed hash (HMAC under a VK-derived key), never by storing passwords twice.
* Usability-security touches: auto-lock after inactivity, clipboard cleared after 30 s, master password asked again before unencrypted CSV export, an offer to delete the plaintext CSV after import, atomic saves.

Known limits (worth mentioning in the report): Python can't reliably wipe strings from memory; an attacker who can write the vault file can roll it back to an older copy or delete a whole entry; strength scoring is a simple heuristic, not zxcvbn.

## Files

* `app.py`: Tkinter UI (screens, dialogs, demo data, Face ID dialogs)
* `vault.py`: vault file, master password and recovery key, biometric wrapping, index, CSV import/export
* `face_auth.py`: deep learning face pipeline (RetinaFace + ArcFace) and DPAPI biometric store
* `passgen.py`: password and passphrase generator, strength check
* `open_locker_demo.py`: per-locker crypto (original walkthrough; still runs on its own)
* `test_vault.py`: unit tests
