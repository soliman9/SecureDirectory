"""
archive_utils.py
Phase 2 - Folder Handling & Archiving

Zips a folder into a single file the crypto core can encrypt, restores it
on the way back out, and shreds temporary/original plaintext when asked.
"""

import os
import shutil


def zip_folder(folder_path: str) -> str:
    """
    Compress folder_path into a .zip sitting next to it (same parent dir).
    The zip's internal root is the folder's own name, so unzip_archive()
    recreates a folder with the original name.
    Returns the path to the created .zip file.
    """
    folder_path = os.path.normpath(folder_path)
    parent_dir = os.path.dirname(folder_path) or "."
    folder_name = os.path.basename(folder_path)
    base_name = os.path.join(parent_dir, folder_name)  # shutil appends ".zip"
    return shutil.make_archive(
        base_name=base_name,
        format="zip",
        root_dir=parent_dir,
        base_dir=folder_name,
    )


def unzip_archive(zip_path: str, extract_to: str) -> None:
    """Restore a folder structure from a zip archive into extract_to."""
    os.makedirs(extract_to, exist_ok=True)
    shutil.unpack_archive(zip_path, extract_dir=extract_to, format="zip")


def secure_delete_file(path: str, passes: int = 3) -> None:
    """
    Overwrite a file with fresh random bytes `passes` times, fsync-ing each
    pass, before finally unlinking it.

    Caveat: on SSDs, and on copy-on-write or journaled filesystems (APFS,
    Btrfs, ZFS, most cloud/network drives), an in-place overwrite is not
    guaranteed to touch the same physical blocks the original data lived
    on - wear-leveling and snapshots can leave recoverable copies behind.
    This is a real improvement over a plain delete on traditional spinning
    disks, but it is not a cryptographic guarantee on modern storage.
    """
    if not os.path.isfile(path):
        return
    length = os.path.getsize(path)
    with open(path, "r+b", buffering=0) as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(length))
            f.flush()
            os.fsync(f.fileno())
    os.remove(path)


def secure_delete_folder(path: str, passes: int = 3) -> None:
    """Recursively shred every file in a folder, then remove the empty dirs."""
    if not os.path.isdir(path):
        return
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            secure_delete_file(os.path.join(root, name), passes=passes)
        for name in dirs:
            try:
                os.rmdir(os.path.join(root, name))
            except OSError:
                pass
    os.rmdir(path)
