# SecureDirectory — folder encryption CLI

Encrypts an entire folder into a single password-protected `.vault` file, and
decrypts it back. Pure Python + the `cryptography` library, cross-platform
(Windows PowerShell / Linux / macOS Bash).

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Encrypt a folder → myfolder.vault (Fernet mode, default)
python securedirectory.py encrypt /path/to/myfolder

# Encrypt with streaming AES-256-GCM instead (recommended for multi-GB folders,
# since it never loads the whole archive into RAM at once)
python securedirectory.py encrypt /path/to/myfolder --stream

# Decrypt back into a folder next to the .vault file
python securedirectory.py decrypt /path/to/myfolder.vault

# Decrypt into a specific directory
python vausecuredirectorylt.py decrypt /path/to/myfolder.vault --output /path/to/restore/here

# Skip the confirmation prompts (useful for scripting)
python vasecuredirectoryult.py encrypt /path/to/myfolder --force
```

You'll be prompted for a password via `getpass` (nothing echoes to the
screen). There is no password recovery — if you lose it, the data is gone.

## How it works

**Phase 1 — Crypto core (`crypto_core.py`)**
- A random 16-byte salt is generated per encryption.
- `PBKDF2HMAC`-SHA256 (480,000 iterations) turns the password + salt into a
  32-byte key.
- **Fernet mode** (default): the whole zipped folder is encrypted in memory
  with `Fernet` — simple, and Fernet's token already includes an IV, version,
  timestamp, and HMAC integrity check.
- **Stream mode** (`--stream`): the zip is encrypted in 64 KiB chunks with
  raw `AES-256-GCM` (`cryptography.hazmat`), each chunk with its own random
  nonce, so memory use stays flat regardless of folder size.

**Phase 2 — Archiving (`archive_utils.py`)**
- `shutil.make_archive` / `shutil.unpack_archive` zip and unzip the folder.
- `secure_delete_file` / `secure_delete_folder` overwrite files with random
  bytes (3 passes by default, `--passes N` to change it) before unlinking
  them. Note: on SSDs and copy-on-write filesystems this is a best-effort
  improvement, not a cryptographic guarantee — wear-leveling and snapshots
  can leave copies elsewhere.

**Phase 3 — Pipeline (`securedirectory.py`)**
- Encrypt: prompt password → zip folder → generate salt → derive key →
  encrypt → write `[magic][mode][salt][ciphertext]` to `.vault` → confirm →
  shred zip + original folder.
- Decrypt: prompt password → read magic/mode/salt → derive key → decrypt →
  unzip → confirm → shred temp zip, remove `.vault`.

## `.vault` file format

```
[4 bytes]  magic   b"PVLT"
[1 byte]   mode    0x01 = Fernet, 0x02 = streamed AES-256-GCM
[16 bytes] salt    random, plaintext (not secret, just unique)
[...]      payload Fernet token, or length-prefixed AES-GCM frames
```

## Security notes

- The password is never written anywhere. Only the salt is stored, in
  plaintext, prepended to the `.vault` file — that's expected and safe.
- A wrong password (or a corrupted/tampered file) fails cleanly: both Fernet
  and AES-GCM verify integrity before returning any plaintext, so you get a
  clear error instead of garbage output.
- Nothing destructive happens without a confirmation prompt (or `--force`
  for scripted use).
