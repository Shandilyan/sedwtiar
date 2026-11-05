"""Privacy-preserving file-type inventory for explicitly selected external volumes.

Only directory-entry metadata (extension and byte size) is read. File names,
paths, timestamps and contents are never retained or sent to the local model.
This is categorization, not a secure-delete operation.
"""

from __future__ import annotations

import base64
from collections import defaultdict
from datetime import datetime
import io
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any
import urllib.error
import urllib.request
import webbrowser

from device_inventory import DeviceInventoryError, get_storage_inventory, is_external_attached


def _post_certificate(payload: dict) -> bytes:
    """POST the payload to the FastAPI certificate endpoint and return raw PDF bytes."""
    import json
    api_url = "http://127.0.0.1:8000/certificate/generate"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(api_url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def _show_pdf_in_popup(pdf_bytes: bytes, suggested_name: str) -> None:
    """Write PDF to a temporary file, open it in the system PDF viewer."""
    fd, tmp_path = tempfile.mkstemp(suffix=".pdf", prefix="cert_")
    os.close(fd)
    with open(tmp_path, "wb") as f:
        f.write(pdf_bytes)

    if sys.platform.startswith("win"):
        os.startfile(tmp_path)
    else:
        webbrowser.open_new(f"file://{tmp_path}")


def generate_and_show_certificate():
    """Collect UI data, request the PDF from the backend, and display it."""
    payload = {
        "company_name": "SEDWTIAR",
        "devices": ["USB-001"],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    try:
        pdf_bytes = _post_certificate(payload)
    except Exception as exc:
        print(f"[Certificate Error] Failed to generate: {exc}")
        return
    suggested_name = f"Sanitisation_{datetime.utcnow():%Y%m%d%H%M%S}.pdf"
    _show_pdf_in_popup(pdf_bytes, suggested_name)


FILE_CATEGORIES: dict[str, frozenset[str]] = {
    "Documents & office files": frozenset({".pdf", ".doc", ".docx", ".odt", ".rtf", ".txt", ".md", ".xls", ".xlsx", ".csv", ".ppt", ".pptx"}),
    "Photos & images": frozenset({".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".webp", ".raw", ".dng", ".svg"}),
    "Video": frozenset({".mp4", ".mov", ".avi", ".mkv", ".m4v", ".wmv", ".webm"}),
    "Audio": frozenset({".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".wma"}),
    "Archives & backups": frozenset({".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".bak", ".backup"}),
    "Databases & structured data": frozenset({".db", ".sqlite", ".sqlite3", ".sql", ".dump", ".json", ".xml", ".parquet"}),
    "Code & scripts": frozenset({".py", ".js", ".ts", ".java", ".c", ".cpp", ".cs", ".go", ".rs", ".html", ".css", ".ps1", ".sh"}),
    "Keys & security-related formats": frozenset({".key", ".pem", ".p12", ".pfx", ".ppk", ".kdbx", ".ovpn", ".env", ".asc"}),
}

_CATEGORY_BY_EXTENSION = {
    extension: category
    for category, extensions in FILE_CATEGORIES.items()
    for extension in extensions
}

WINDOWS_FILE_ATTRIBUTE_HIDDEN = 0x2
WINDOWS_FILE_ATTRIBUTE_SYSTEM = 0x4
WINDOWS_SYSTEM_ITEM_CATEGORY = "Windows system-marked items"

PROTECTED_SYSTEM_DIRECTORIES = frozenset({
    "$recycle.bin",
    "system volume information",
    "recycler",
    "found.000",
    "found.001",
    "found.002",
    "efi",
    "boot",
    "rufus_boot",
    ".trashes",
    ".spotlight-v100",
    ".fseventsd",
    ".temporaryitems",
    "msdownld.tmp",
})

SYSTEM_METADATA_FILES = frozenset({
    "desktop.ini",
    "thumbs.db",
    "indexervolumeguid",
    "wpsettings.dat",
    "autorun.inf",
})


def is_system_directory(name: str, attributes: int = 0) -> bool:
    """Return True if the directory is an OS/filesystem internal directory (e.g. Recycle Bin or System Volume Information)."""
    name_lower = name.casefold()
    if name_lower in PROTECTED_SYSTEM_DIRECTORIES:
        return True
    if name_lower.startswith("found.") and (len(name_lower) == 6 or name_lower[6:].isdigit()):
        return True
    if bool(attributes & WINDOWS_FILE_ATTRIBUTE_SYSTEM):
        return True
    return False


def is_system_file(name: str, attributes: int = 0) -> bool:
    """Return True if the file is an OS metadata/system file that is not user content."""
    name_lower = name.casefold()
    if name_lower in SYSTEM_METADATA_FILES:
        return True
    if bool(attributes & WINDOWS_FILE_ATTRIBUTE_SYSTEM):
        return True
    return False


def classify_file_metadata(file_name: str, windows_attributes: int = 0) -> tuple[str, str | None]:
    """Separate system-marked entries while retaining types for hidden user files."""
    entry_name = file_name.casefold()
    extension = entry_name if entry_name == ".env" else Path(file_name).suffix.casefold()
    extension = extension or "(no extension)"
    category = _CATEGORY_BY_EXTENSION.get(extension, "Other / unknown type")
    if windows_attributes & WINDOWS_FILE_ATTRIBUTE_SYSTEM:
        return WINDOWS_SYSTEM_ITEM_CATEGORY, None
    if windows_attributes & WINDOWS_FILE_ATTRIBUTE_HIDDEN:
        return f"Hidden files · {category}", extension
    return category, extension


class FileScanError(RuntimeError):
    """Raised when a selected external volume is no longer safe to inspect."""


def describe_volume_scan_error(drive_letter: str, error: OSError) -> str:
    """Return a useful, non-destructive explanation for Windows volume errors."""
    if getattr(error, "winerror", None) == 1005:
        return (
            f"Windows cannot read {drive_letter.upper()}: because it has no recognized file system. "
            "This can occur after a whole-device overwrite or when the volume is corrupted. "
            "File-type scanning is unavailable; no files were read or changed."
        )
    return f"Windows could not read {drive_letter.upper()}: for file-type scanning: {error}"


def scan_external_volume(
    drive_letter: str,
    expected_fingerprint: str,
    *,
    max_files: int = 500_000,
    max_depth: int = 64,
) -> dict[str, Any]:
    """Count file types on a revalidated external volume without reading files."""
    if os.name != "nt":
        raise FileScanError("File-type inventory is currently supported on Windows only.")
    if not re.fullmatch(r"[A-Za-z]", drive_letter or ""):
        raise FileScanError("Choose a valid external-volume drive letter.")

    try:
        inventory = get_storage_inventory()
    except DeviceInventoryError as exc:
        raise FileScanError(f"Could not revalidate the selected drive: {exc}") from exc

    selected = next(
        (disk for disk in inventory["disks"] if disk["fingerprint"] == expected_fingerprint),
        None,
    )
    if selected is None:
        raise FileScanError("The selected device changed or was disconnected. Refresh the device list.")
    if selected["protected"]:
        raise FileScanError("This device contains a Windows boot/system partition and is protected.")
    if not is_external_attached(selected):
        raise FileScanError("The selected disk is not identified as externally attached; internal disks are inventory-only.")
    if not any(
        str(partition.get("drive_letter") or "").casefold() == drive_letter.casefold()
        for partition in selected["partitions"]
    ):
        raise FileScanError("The selected volume is no longer mounted on this device.")

    root = Path(f"{drive_letter.upper()}:\\")
    try:
        # Explicitly check that Windows can enumerate the root.  Path.is_dir()
        # hides some Windows file-system errors, including WinError 1005.
        with os.scandir(root):
            pass
    except OSError as exc:
        raise FileScanError(describe_volume_scan_error(drive_letter, exc)) from exc

    category_counts: dict[str, int] = defaultdict(int)
    category_bytes: dict[str, int] = defaultdict(int)
    extension_counts: dict[str, int] = defaultdict(int)
    file_count = 0
    directory_count = 0
    inaccessible_count = 0
    truncated = False
    pending: list[tuple[Path, int]] = [(root, 0)]

    while pending:
        directory, depth = pending.pop()
        if depth > max_depth:
            inaccessible_count += 1
            continue
        try:
            entries = os.scandir(directory)
        except OSError as exc:
            if directory == root:
                raise FileScanError(describe_volume_scan_error(drive_letter, exc)) from exc
            inaccessible_count += 1
            continue
        with entries:
            for entry in entries:
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        dir_stat = None
                        try:
                            dir_stat = entry.stat(follow_symlinks=False)
                        except OSError:
                            pass
                        dir_attrs = getattr(dir_stat, "st_file_attributes", 0) if dir_stat else 0
                        if is_system_directory(entry.name, dir_attrs):
                            continue
                        directory_count += 1
                        pending.append((Path(entry.path), depth + 1))
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    file_stat = entry.stat(follow_symlinks=False)
                    size = file_stat.st_size
                    attributes = getattr(file_stat, "st_file_attributes", 0)
                    if is_system_file(entry.name, attributes):
                        continue
                    if file_count >= max_files:
                        truncated = True
                        pending.clear()
                        break
                    category, extension = classify_file_metadata(entry.name, attributes)
                    file_count += 1
                    category_counts[category] += 1
                    category_bytes[category] += size
                    if extension is not None:
                        extension_counts[extension] += 1
                except OSError:
                    inaccessible_count += 1

    categories = [
        {"category": category, "files": count, "bytes": category_bytes[category]}
        for category, count in sorted(category_counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    extensions = [
        {"extension": extension, "files": count}
        for extension, count in sorted(extension_counts.items(), key=lambda item: (-item[1], item[0]))[:30]
    ]
    risk_assessment = None
    try:
        from risk_model import compute_device_risk_score
        risk_assessment = compute_device_risk_score(categories)
    except Exception:
        pass

    return {
        "drive_letter": drive_letter.upper(),
        "device_name": selected["name"],
        "device_fingerprint": selected["fingerprint"],
        "files_counted": file_count,
        "directories_seen": directory_count,
        "inaccessible_entries": inaccessible_count,
        "truncated_at_limit": truncated,
        "categories": categories,
        "common_extensions": extensions,
        "risk_assessment": risk_assessment,
        "privacy_note": "Names, paths and file contents were not collected; only extension and size aggregates are returned.",
        "secure_delete_notice": "File-type detection does not establish that an individual file was securely erased.",
    }


def scan_removable_volume(
    drive_letter: str,
    expected_fingerprint: str,
    *,
    max_files: int = 500_000,
    max_depth: int = 64,
) -> dict[str, Any]:
    """Backward-compatible name for scanning an eligible external volume."""
    return scan_external_volume(
        drive_letter,
        expected_fingerprint,
        max_files=max_files,
        max_depth=max_depth,
    )
