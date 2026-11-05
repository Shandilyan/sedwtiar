"""Best-effort overwrite and removal of selected hidden non-system files.

The overwrite is limited to the file's current host-visible allocation and
cannot guarantee sanitization on flash media due to controller remapping,
overprovisioning, filesystem behavior, or device caches. It never follows
reparse points, operates only on a revalidated external volume, and refuses
files or directories carrying Windows' System attribute.
"""

from __future__ import annotations

import ctypes
import os
import re
import stat
from pathlib import Path, PureWindowsPath
from typing import Any, Iterable

from device_inventory import DeviceInventoryError, get_storage_inventory, is_external_attached


FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_READONLY = 0x1
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
# Sequential sixteen-MiB buffers lower Python and filesystem-call overhead for
# large HDD/SSD files while keeping the per-file working set bounded. Read-back
# remains enabled and the operation is still not represented as sanitization.
OVERWRITE_CHUNK_SIZE = 16 * 1024 * 1024
PROTECTED_DIRECTORY_NAMES = frozenset({
    "$recycle.bin", "recycler", "system volume information", "found.000",
    "efi", "boot", "rufus_boot",
})

class MediaPruningError(RuntimeError):
    """Raised when the chosen external volume or hidden-file operation is unsafe."""


def _validated_volume(drive_letter: str, expected_fingerprint: str) -> tuple[Path, dict[str, Any]]:
    if os.name != "nt":
        raise MediaPruningError("External-drive file operations are supported on Windows only.")
    if not re.fullmatch(r"[A-Za-z]", drive_letter or ""):
        raise MediaPruningError("Choose a valid drive letter.")
    try:
        inventory = get_storage_inventory()
    except DeviceInventoryError as exc:
        raise MediaPruningError(f"Could not revalidate the selected drive: {exc}") from exc
    disk = next(
        (item for item in inventory["disks"] if item["fingerprint"] == expected_fingerprint),
        None,
    )
    if disk is None:
        raise MediaPruningError("The selected device changed or was disconnected. Refresh the device list.")
    if disk["protected"]:
        raise MediaPruningError("This disk is marked as a Windows boot/system disk; changes are blocked.")
    if not is_external_attached(disk):
        raise MediaPruningError("The selected disk is not identified as external; internal disks are blocked.")
    if disk.get("is_read_only") or disk.get("is_offline"):
        raise MediaPruningError("Windows reports this external disk as read-only or offline; changes are blocked.")
    if not any(
        str(part.get("drive_letter") or "").casefold() == drive_letter.casefold()
        for part in disk["partitions"]
    ):
        raise MediaPruningError("The selected drive letter no longer belongs to this external device.")
    root = Path(f"{drive_letter.upper()}:\\")
    if not root.is_dir():
        raise MediaPruningError("The selected external volume is not available.")
    return root, disk


def _is_reparse(attributes: int) -> bool:
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


def _is_protected_directory(name: str, attributes: int) -> bool:
    return bool(attributes & FILE_ATTRIBUTE_SYSTEM) or name.casefold() in PROTECTED_DIRECTORY_NAMES


def list_hidden_user_files(
    drive_letter: str,
    expected_fingerprint: str,
    *,
    max_files: int = 20_000,
    max_depth: int = 48,
) -> dict[str, Any]:
    """Preview hidden, non-system files only; paths stay local and are not sent to Gemma."""
    root, disk = _validated_volume(drive_letter, expected_fingerprint)
    candidates: list[dict[str, Any]] = []
    protected_skipped = 0
    inaccessible = 0
    truncated = False
    pending: list[tuple[Path, int]] = [(root, 0)]
    root_resolved = root.resolve()

    while pending:
        directory, depth = pending.pop()
        if depth > max_depth:
            inaccessible += 1
            continue
        try:
            entries = os.scandir(directory)
        except OSError:
            inaccessible += 1
            continue
        with entries:
            for entry in entries:
                try:
                    if entry.is_symlink():
                        continue
                    metadata = entry.stat(follow_symlinks=False)
                    attributes = getattr(metadata, "st_file_attributes", 0)
                    if _is_reparse(attributes):
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if _is_protected_directory(entry.name, attributes):
                            protected_skipped += 1
                            continue
                        pending.append((Path(entry.path), depth + 1))
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    if attributes & FILE_ATTRIBUTE_SYSTEM:
                        protected_skipped += 1
                        continue
                    if not attributes & FILE_ATTRIBUTE_HIDDEN:
                        continue
                    full_path = Path(entry.path).resolve(strict=True)
                    full_path.relative_to(root_resolved)
                    relative = full_path.relative_to(root_resolved).as_posix()
                    candidates.append({
                        "relative_path": relative,
                        "bytes": int(metadata.st_size),
                        "read_only": bool(attributes & FILE_ATTRIBUTE_READONLY or not os.access(full_path, os.W_OK)),
                    })
                    if len(candidates) >= max_files:
                        truncated = True
                        pending.clear()
                        break
                except (OSError, ValueError):
                    inaccessible += 1

    return {
        "drive_letter": drive_letter.upper(),
        "device_name": disk["name"],
        "candidates": candidates,
        "protected_system_items_skipped": protected_skipped,
        "inaccessible_entries": inaccessible,
        "truncated_at_limit": truncated,
        "operation": "filesystem unlink preview only; not secure media sanitization",
    }


def _safe_relative_parts(relative_path: str) -> tuple[str, ...]:
    candidate = PureWindowsPath(relative_path)
    if candidate.is_absolute() or candidate.drive or not candidate.parts:
        raise MediaPruningError("A preview path was not a relative file path.")
    if any(part in {".", ".."} for part in candidate.parts):
        raise MediaPruningError("A preview path attempted to leave the selected volume.")
    return candidate.parts


def prune_hidden_user_files(
    drive_letter: str,
    expected_fingerprint: str,
    relative_paths: Iterable[str],
) -> dict[str, Any]:
    """Best-effort overwrite then unlink only files listed in the confirmed preview.

    The read-back confirms only the host-visible file contents. It cannot verify
    stale flash cells, filesystem snapshots/journals, caches, or remapped blocks.
    """
    root, disk = _validated_volume(drive_letter, expected_fingerprint)
    paths = list(relative_paths)
    if not paths or len(set(paths)) != len(paths):
        raise MediaPruningError("Choose one or more distinct files from the current preview.")

    targets: list[Path] = []
    root_resolved = root.resolve()
    for relative_path in paths:
        parts = _safe_relative_parts(relative_path)
        target = root.joinpath(*parts)
        try:
            resolved = target.resolve(strict=True)
            resolved.relative_to(root_resolved)
            metadata = target.lstat()
        except (OSError, ValueError) as exc:
            raise MediaPruningError("A selected path changed or escaped the external volume; nothing was deleted.") from exc
        attributes = getattr(metadata, "st_file_attributes", 0)
        if not stat.S_ISREG(metadata.st_mode) or _is_reparse(attributes):
            raise MediaPruningError("A selected entry is no longer a regular file; nothing was deleted.")
        if attributes & FILE_ATTRIBUTE_SYSTEM:
            raise MediaPruningError("System-marked files are protected; nothing was deleted.")
        if not attributes & FILE_ATTRIBUTE_HIDDEN:
            raise MediaPruningError("A selected file is no longer hidden; nothing was deleted.")
        if attributes & FILE_ATTRIBUTE_READONLY:
            raise MediaPruningError("Read-only files are protected; nothing was deleted.")
        targets.append(target)

    deleted: list[dict[str, Any]] = []
    failed: list[str] = []
    overwritten_count = 0
    for target, relative_path in zip(targets, paths):
        try:
            size = target.stat().st_size
            _overwrite_file_and_verify(target, size)
            overwritten_count += 1
            target.unlink()
            deleted.append({"relative_path": relative_path, "bytes": size})
        except OSError:
            failed.append(relative_path)
    return {
        "drive_letter": drive_letter.upper(),
        "device_name": disk["name"],
        "deleted": deleted,
        "failed": failed,
        "operation": "best-effort zero overwrite/read-back of current file allocation, then unlink",
        "files_zero_overwritten_and_verified": overwritten_count,
        "host_visible_overwrite_verified": overwritten_count == len(paths),
        "secure_sanitization": False,
        "assurance": "Not guaranteed secure deletion; flash remapping, overprovisioning, filesystem copies, and device caches are not verified.",
    }


def _overwrite_file_and_verify(path: Path, size_bytes: int) -> None:
    """Overwrite a selected file's current logical contents with zeroes and read back."""
    zero_chunk = bytes(OVERWRITE_CHUNK_SIZE)
    with path.open("r+b", buffering=0) as stream:
        remaining = size_bytes
        stream.seek(0)
        while remaining:
            chunk = memoryview(zero_chunk)[:min(remaining, len(zero_chunk))]
            written = stream.write(chunk)
            if written is None or written <= 0:
                raise OSError("Short write while overwriting selected file")
            remaining -= written
        stream.flush()
        os.fsync(stream.fileno())
        stream.seek(0)
        remaining = size_bytes
        read_buffer = bytearray(min(OVERWRITE_CHUNK_SIZE, max(size_bytes, 1)))
        while remaining:
            read_size = min(remaining, len(read_buffer))
            read_count = stream.readinto(memoryview(read_buffer)[:read_size])
            if read_count != read_size or any(read_buffer[:read_count]):
                raise OSError("Selected file zero read-back did not verify")
            remaining -= read_count
