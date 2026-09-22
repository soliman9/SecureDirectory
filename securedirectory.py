#!/usr/bin/env python3
"""
securedirectory.py

.vault file layout:
    [4 bytes]  magic     b"PVLT"
    [1 byte]   mode      0x01 = Fernet   (whole archive encrypted in memory)
                          0x02 = STREAM  (AES-256-GCM, chunked)
    [16 bytes] salt       random, unique per encryption, stored in plaintext
    [ ... ]    payload    Fernet token, or length-prefixed AES-GCM frames
                          (see crypto_core.py for the exact frame format)

Usage:
    python securedirectory.py encrypt /path/to/folder [--stream] [--force] [--passes N]
    python securedirectory.py decrypt /path/to/folder.vault [--output DIR] [--force] [--passes N]

Run on Windows PowerShell or Linux/macOS Bash identically - everything here
is pure Python + the standard library + `cryptography`.
"""

import argparse
import getpass
import os
import sys

import archive_utils
import crypto_core

MAGIC = b"PVLT"
MODE_FERNET = 0x01
MODE_STREAM = 0x02
VAULT_EXT = ".vault"


# ---------------------------------------------------------------- utilities

def prompt_new_password() -> str:
    while True:
        pw1 = getpass.getpass("Enter a password to encrypt the vault: ")
        if len(pw1) < 8:
            print("Password should be at least 8 characters. Try again.")
            continue
        pw2 = getpass.getpass("Confirm password: ")
        if pw1 != pw2:
            print("Passwords did not match. Try again.")
            continue
        return pw1


def prompt_existing_password() -> str:
    return getpass.getpass("Enter password to decrypt the vault: ")


def confirm(prompt: str, force: bool) -> bool:
    if force:
        return True
    return input(f"{prompt} [y/N]: ").strip().lower() == "y"


# ------------------------------------------------------------ encrypt flow

def encrypt_flow(folder_path: str, stream: bool, force: bool, passes: int) -> None:
    folder_path = os.path.normpath(folder_path)
    if not os.path.isdir(folder_path):
        print(f"Error: '{folder_path}' is not a folder.")
        sys.exit(1)

    vault_path = folder_path + VAULT_EXT
    if os.path.exists(vault_path) and not confirm(
        f"'{vault_path}' already exists and will be overwritten. Continue?", force
    ):
        print("Aborted.")
        return

    password = prompt_new_password()

    print(f"Zipping '{folder_path}' ...")
    zip_path = archive_utils.zip_folder(folder_path)

    salt = os.urandom(crypto_core.SALT_SIZE)
    mode = MODE_STREAM if stream else MODE_FERNET

    print(f"Encrypting ({'streamed AES-256-GCM' if stream else 'Fernet'}) ...")
    try:
        with open(vault_path, "wb") as out:
            out.write(MAGIC)
            out.write(bytes([mode]))
            out.write(salt)
            if mode == MODE_FERNET:
                with open(zip_path, "rb") as zf:
                    data = zf.read()
                out.write(crypto_core.fernet_encrypt(data, password, salt))
            else:
                crypto_core.stream_encrypt_file(zip_path, out, password, salt)
    except Exception as exc:
        print(f"Encryption failed: {exc}")
        if os.path.exists(vault_path):
            os.remove(vault_path)  # don't leave a half-written vault around
        sys.exit(1)

    if not confirm(
        f"Delete the original folder '{folder_path}' and the temporary zip? "
        f"(the encrypted '{vault_path}' will remain either way)",
        force,
    ):
        print(f"Vault created at '{vault_path}'. Original folder and zip left in place.")
        return

    print("Shredding temporary zip ...")
    archive_utils.secure_delete_file(zip_path, passes=passes)

    print("Shredding original folder ...")
    archive_utils.secure_delete_folder(folder_path, passes=passes)

    print(f"Done. Encrypted vault written to '{vault_path}'.")


# ------------------------------------------------------------ decrypt flow

def decrypt_flow(vault_path: str, force: bool, output_dir: str, passes: int) -> None:
    vault_path = os.path.normpath(vault_path)
    if not os.path.isfile(vault_path):
        print(f"Error: '{vault_path}' is not a file.")
        sys.exit(1)

    password = prompt_existing_password()

    base_name = os.path.basename(vault_path)
    if base_name.endswith(VAULT_EXT):
        base_name = base_name[: -len(VAULT_EXT)]
    target_dir = output_dir or os.path.dirname(vault_path) or "."
    zip_path = os.path.join(target_dir, base_name + ".zip")

    with open(vault_path, "rb") as f:
        magic = f.read(4)
        if magic != MAGIC:
            print("Error: this does not look like a valid .vault file.")
            sys.exit(1)
        mode = f.read(1)[0]
        salt = f.read(crypto_core.SALT_SIZE)

        print("Decrypting ...")
        try:
            if mode == MODE_FERNET:
                data = crypto_core.fernet_decrypt(f.read(), password, salt)
                with open(zip_path, "wb") as zf:
                    zf.write(data)
            elif mode == MODE_STREAM:
                crypto_core.stream_decrypt_file(f, zip_path, password, salt)
            else:
                print("Error: unrecognized vault mode - file may be corrupted.")
                sys.exit(1)
        except ValueError as exc:
            print(str(exc))
            if os.path.exists(zip_path):
                os.remove(zip_path)
            sys.exit(1)

    print(f"Restoring folder into '{target_dir}' ...")
    archive_utils.unzip_archive(zip_path, target_dir)

    if not confirm(f"Delete the vault file '{vault_path}' and the temporary zip?", force):
        print("Vault and temporary zip left in place.")
        return

    print("Removing temporary zip ...")
    archive_utils.secure_delete_file(zip_path, passes=passes)

    print("Removing vault file ...")
    os.remove(vault_path)  # this is ciphertext only, no plaintext to shred

    print(f"Done. Folder restored under '{target_dir}'.")


# ---------------------------------------------------------------------- CLI

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault.py",
        description="Encrypt or decrypt a folder into a password-protected .vault file.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt a folder into a .vault file.")
    enc.add_argument("folder", help="Path to the folder to encrypt.")
    enc.add_argument(
        "--stream", action="store_true",
        help="Use chunked AES-256-GCM streaming instead of Fernet. Recommended "
             "for very large folders (multi-GB) so the whole archive never "
             "has to sit in RAM at once.",
    )
    enc.add_argument("--force", "-y", action="store_true",
                      help="Skip confirmation prompts (for scripting).")
    enc.add_argument("--passes", type=int, default=3,
                      help="Random-overwrite passes for secure deletion (default: 3).")

    dec = sub.add_parser("decrypt", help="Decrypt a .vault file back into a folder.")
    dec.add_argument("vault_file", help="Path to the .vault file to decrypt.")
    dec.add_argument("--output", default=None,
                      help="Directory to restore the folder into "
                           "(default: same folder the .vault file is in).")
    dec.add_argument("--force", "-y", action="store_true",
                      help="Skip confirmation prompts (for scripting).")
    dec.add_argument("--passes", type=int, default=3,
                      help="Random-overwrite passes for secure deletion (default: 3).")

    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "encrypt":
        encrypt_flow(args.folder, stream=args.stream, force=args.force, passes=args.passes)
    elif args.command == "decrypt":
        decrypt_flow(args.vault_file, force=args.force, output_dir=args.output, passes=args.passes)


if __name__ == "__main__":
    main()
