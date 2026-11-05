"""Windows whole-device logical overwrite for an explicitly confirmed external disk.

This writes zeroes to every host-addressable logical block and reads them back.
It is deliberately called an overwrite, not secure sanitization: flash-controller
overprovisioning, remapped cells, or firmware behavior may retain prior data.
The operation is destructive and must only be invoked after the UI's explicit
typed confirmation. This module is never called automatically at application start.
"""

from __future__ import annotations

import ctypes
import io
import msvcrt
import os
import re
import struct
import time
from ctypes import wintypes
from typing import Any, Callable

from device_inventory import DeviceInventoryError, get_storage_inventory, is_external_attached
from media_pruning import MediaPruningError


GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_WRITE_THROUGH = 0x80000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

FSCTL_LOCK_VOLUME = 0x00090018
FSCTL_DISMOUNT_VOLUME = 0x00090020
IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0
IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x00070000
STORAGE_ACCESS_ALIGNMENT_PROPERTY = 6
# Larger sequential transfers substantially reduce Python/Windows call overhead
# on HDDs and SSDs.  The baseline is deliberately bounded; an external SSD gets
# a larger buffer because its sustained sequential throughput can make Python
# call overhead visible. Full read-back is intentionally retained: skipping it
# would make the operation faster only by removing the evidence check.
TRANSFER_SIZE = 16 * 1024 * 1024
SSD_TRANSFER_SIZE = 32 * 1024 * 1024


class PhysicalOverwriteError(RuntimeError):
    """Raised when a requested logical overwrite cannot safely complete."""


def confirmation_phrase(disk: dict[str, Any]) -> str:
    size_gb = int(disk.get("size_bytes") or 0) / (1024 ** 3)
    label = re.sub(r"[^A-Z0-9]+", "_", str(disk.get("name") or "USB_DEVICE").upper()).strip("_")
    return f"OVERWRITE DISK {int(disk['number'])} {label} {size_gb:.1f}GB"


def recommended_transfer_size(media_type: str | None, device_name: str | None = None) -> int:
    """Return a bounded sequential buffer size without changing wipe semantics.

    Some USB bridges omit Windows' physical-media classification but retain
    "SSD" in the friendly name. This affects buffer sizing only; it never
    changes target eligibility, overwrite scope, or assurance language.
    """
    normalized = f"{media_type or ''} {device_name or ''}".casefold()
    return SSD_TRANSFER_SIZE if "ssd" in normalized or "solid state" in normalized else TRANSFER_SIZE


def _selected_disk(drive_letter: str, fingerprint: str) -> dict[str, Any]:
    if os.name != "nt":
        raise PhysicalOverwriteError("Physical-device overwrite is available on Windows only.")
    if not re.fullmatch(r"[A-Za-z]", drive_letter or ""):
        raise PhysicalOverwriteError("Choose a valid external-volume drive letter.")
    try:
        inventory = get_storage_inventory()
    except DeviceInventoryError as exc:
        raise PhysicalOverwriteError(f"Could not revalidate the target: {exc}") from exc
    disk = next((item for item in inventory["disks"] if item["fingerprint"] == fingerprint), None)
    if disk is None:
        raise PhysicalOverwriteError("The device identity changed or it was disconnected. Nothing was written.")
    if disk.get("protected"):
        raise PhysicalOverwriteError("Boot/system disks are blocked. Nothing was written.")
    if not is_external_attached(disk):
        raise PhysicalOverwriteError(
            "Only a Windows-identified external USB/SD/MMC/1394 disk is eligible. "
            "Internal HDD/SSD disks are inventory-only and are blocked."
        )
    if disk.get("is_read_only") or disk.get("is_offline"):
        raise PhysicalOverwriteError("Windows reports this external disk as read-only or offline; overwrite is blocked.")
    partitions = disk.get("partitions", [])
    letters = [str(part.get("drive_letter") or "").upper() for part in partitions]
    if not any(letter.casefold() == drive_letter.casefold() for letter in letters):
        raise PhysicalOverwriteError("The chosen volume no longer belongs to the confirmed removable disk.")
    if not letters or any(not re.fullmatch(r"[A-Z]", letter) for letter in letters):
        raise PhysicalOverwriteError("A disk partition has no drive letter; the target scope is ambiguous, so overwrite is blocked.")
    if int(disk.get("size_bytes") or 0) <= 0 or int(disk["number"]) < 0:
        raise PhysicalOverwriteError("Windows returned invalid disk identity or size metadata.")
    return disk


def _configure_kernel32():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    )
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.DeviceIoControl.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
        wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    )
    kernel32.DeviceIoControl.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _device_io(kernel32, handle, code: int, in_buffer=None, in_size: int = 0, out_buffer=None, out_size: int = 0):
    returned = wintypes.DWORD()
    success = kernel32.DeviceIoControl(
        handle,
        code,
        in_buffer,
        in_size,
        out_buffer,
        out_size,
        ctypes.byref(returned),
        None,
    )
    if not success:
        raise OSError(ctypes.get_last_error(), f"DeviceIoControl 0x{code:08X} failed")
    return returned.value


def _open_volume_lock(kernel32, letter: str):
    handle = kernel32.CreateFileW(
        rf"\\.\{letter}:",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        error_code = ctypes.get_last_error()
        if error_code == 5:
            raise PhysicalOverwriteError(
                f"Windows denied access to volume {letter}:. Run SEDWTIAR as Administrator, "
                "close File Explorer windows and apps using the USB, then retry. No disk bytes were overwritten."
            )
        raise OSError(error_code, f"Could not open volume {letter}:")
    try:
        try:
            _device_io(kernel32, handle, FSCTL_LOCK_VOLUME)
        except OSError as exc:
            if exc.errno == 5:
                raise PhysicalOverwriteError(
                    f"Windows could not exclusively lock volume {letter}:. Run SEDWTIAR as Administrator, "
                    "close File Explorer windows, terminals, and other apps using the USB, then refresh and retry. "
                    "No disk bytes were overwritten."
                ) from exc
            raise
        try:
            _device_io(kernel32, handle, FSCTL_DISMOUNT_VOLUME)
        except OSError as exc:
            if exc.errno == 5:
                raise PhysicalOverwriteError(
                    f"Windows locked volume {letter}: but denied dismounting it. Close apps using the USB, "
                    "then retry. No disk bytes were overwritten."
                ) from exc
            raise
    except Exception:
        kernel32.CloseHandle(handle)
        raise
    return handle


def _is_elevated() -> bool:
    """Return whether this process has an elevated Windows Administrator token."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _physical_device_and_sector_size(kernel32, disk: dict[str, Any]):
    handle = kernel32.CreateFileW(
        rf"\\.\PhysicalDrive{int(disk['number'])}",
        GENERIC_READ | GENERIC_WRITE,
        0,
        None,
        OPEN_EXISTING,
        FILE_FLAG_WRITE_THROUGH,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise OSError(ctypes.get_last_error(), "Could not obtain exclusive physical-disk access")
    try:
        # The current inventory is revalidated immediately before this open and
        # again after all mounted volumes are locked.  Some USB bridges reject
        # IOCTL_STORAGE_GET_DEVICE_NUMBER even when \\.\PhysicalDriveN is valid,
        # so do not make that redundant query a compatibility blocker.
        logical_sector = _query_logical_sector_size(kernel32, handle)
        size_bytes = int(disk["size_bytes"])
        if logical_sector < 512 or logical_sector > 65536 or size_bytes % logical_sector:
            raise PhysicalOverwriteError("Logical-sector geometry was not valid; overwrite is blocked.")
        return handle, logical_sector
    except Exception:
        kernel32.CloseHandle(handle)
        raise


def _query_logical_sector_size(kernel32, handle) -> int:
    """Query sector size, falling back to standard disk geometry for USB drivers."""
    # STORAGE_PROPERTY_QUERY: property ID, standard query, reserved parameters.
    query = (ctypes.c_ubyte * 12)()
    struct.pack_into("<II", query, 0, STORAGE_ACCESS_ALIGNMENT_PROPERTY, 0)
    alignment = ctypes.create_string_buffer(64)
    try:
        _device_io(
            kernel32,
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            in_buffer=query,
            in_size=ctypes.sizeof(query),
            out_buffer=alignment,
            out_size=ctypes.sizeof(alignment),
        )
        return struct.unpack_from("<I", alignment.raw, 16)[0]
    except OSError as property_error:
        # Some USB mass-storage bridges do not implement this storage property.
        # Geometry is a read-only standard IOCTL and provides BytesPerSector in
        # the nested DISK_GEOMETRY at offset 20 of DISK_GEOMETRY_EX.
        geometry = ctypes.create_string_buffer(32)
        try:
            _device_io(
                kernel32,
                handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                out_buffer=geometry,
                out_size=ctypes.sizeof(geometry),
            )
        except OSError as geometry_error:
            # Older USB bridges may implement only the original geometry IOCTL.
            legacy_geometry = ctypes.create_string_buffer(24)
            try:
                _device_io(
                    kernel32,
                    handle,
                    IOCTL_DISK_GET_DRIVE_GEOMETRY,
                    out_buffer=legacy_geometry,
                    out_size=ctypes.sizeof(legacy_geometry),
                )
            except OSError as legacy_error:
                raise PhysicalOverwriteError(
                    "Windows could not report the USB's logical sector size. "
                    f"Storage-property query failed ({property_error}); "
                    f"extended geometry query failed ({geometry_error}); "
                    f"legacy geometry query failed ({legacy_error}). No disk bytes were overwritten."
                ) from legacy_error
            return struct.unpack_from("<I", legacy_geometry.raw, 20)[0]
        return struct.unpack_from("<I", geometry.raw, 20)[0]


def _write_and_verify_fd(
    fd: int,
    size_bytes: int,
    logical_sector: int,
    progress: Callable[[str, int, int], None] | None = None,
    transfer_size: int = TRANSFER_SIZE,
) -> dict[str, float | int]:
    chunk_size = transfer_size - (transfer_size % logical_sector)
    if chunk_size <= 0:
        raise PhysicalOverwriteError("Unsupported logical-sector size.")

    def report(phase: str, done: int):
        if progress:
            progress(phase, done, size_bytes)

    # FileIO.readinto reuses the same verification buffer.  This avoids a new
    # Python bytes allocation for every chunk on multi-terabyte external media.
    # Duplicate the descriptor so closing the FileIO does not close its caller's
    # physical-device handle.
    raw = io.FileIO(os.dup(fd), "r+")
    try:
        started_at = time.monotonic()
        total_written = 0
        zero_chunk = bytes(chunk_size)
        while total_written < size_bytes:
            target_size = min(chunk_size, size_bytes - total_written)
            view = memoryview(zero_chunk)[:target_size]
            written_for_chunk = 0
            while written_for_chunk < target_size:
                written = raw.write(view[written_for_chunk:])
                if written is None or written <= 0:
                    raise PhysicalOverwriteError(
                        f"Overwrite stopped after {total_written + written_for_chunk} bytes; the device may be partially changed."
                    )
                written_for_chunk += written
            total_written += target_size
            report("overwrite", total_written)
        raw.flush()
        os.fsync(raw.fileno())
        write_seconds = time.monotonic() - started_at

        raw.seek(0)
        verify_started_at = time.monotonic()
        verified = 0
        read_buffer = bytearray(chunk_size)
        while verified < size_bytes:
            target_size = min(chunk_size, size_bytes - verified)
            view = memoryview(read_buffer)[:target_size]
            read_count = raw.readinto(view)
            if read_count != target_size or any(view[:read_count]):
                raise PhysicalOverwriteError(
                    f"Logical read-back check failed at byte offset {verified}; the device may be partially changed."
                )
            verified += read_count
            report("verify", verified)
        verify_seconds = time.monotonic() - verify_started_at
    finally:
        raw.close()
    return {
        "write_seconds": write_seconds,
        "verify_seconds": verify_seconds,
        "elapsed_seconds": time.monotonic() - started_at,
        "transfer_size": chunk_size,
    }


def overwrite_external_disk(
    drive_letter: str,
    expected_fingerprint: str,
    typed_confirmation: str,
    progress: Callable[[str, int, int], None] | None = None,
) -> dict[str, Any]:
    """Overwrite all host-addressable blocks of one revalidated external disk.

    External USB-attached HDDs and SSDs are eligible when Windows identifies
    their bus accordingly.  Internal disks remain deliberately blocked.
    """
    disk = _selected_disk(drive_letter, expected_fingerprint)
    expected_phrase = confirmation_phrase(disk)
    if typed_confirmation != expected_phrase:
        raise PhysicalOverwriteError("Confirmation text did not match. Nothing was written.")
    if not _is_elevated():
        raise PhysicalOverwriteError(
            "Administrator permission is required to lock USB volumes and access the physical disk. "
            "Close this app and relaunch it from an Administrator PowerShell window. No disk bytes were overwritten."
        )

    kernel32 = _configure_kernel32()
    volume_handles = []
    physical_handle = None
    fd = None
    try:
        for letter in sorted({str(part["drive_letter"]).upper() for part in disk["partitions"]}):
            volume_handles.append(_open_volume_lock(kernel32, letter))

        # Revalidate after volume locks and before obtaining the whole-disk handle.
        rechecked = _selected_disk(drive_letter, expected_fingerprint)
        if rechecked["number"] != disk["number"] or rechecked["size_bytes"] != disk["size_bytes"]:
            raise PhysicalOverwriteError("Target identity changed during preparation. Nothing was written.")
        physical_handle, logical_sector = _physical_device_and_sector_size(kernel32, disk)
        fd = msvcrt.open_osfhandle(physical_handle, os.O_BINARY | os.O_RDWR)
        physical_handle = None  # ownership transferred to fd
        performance = _write_and_verify_fd(
            fd,
            int(disk["size_bytes"]),
            logical_sector,
            progress,
            transfer_size=recommended_transfer_size(disk.get("media_type"), disk.get("name")),
        )
    except PhysicalOverwriteError:
        raise
    except Exception as exc:
        raise PhysicalOverwriteError(
            f"Overwrite did not complete: {exc}. If any bytes had already been written, the disk may be partially changed."
        ) from exc
    finally:
        if fd is not None:
            os.close(fd)
        if physical_handle is not None:
            kernel32.CloseHandle(physical_handle)
        for handle in reversed(volume_handles):
            kernel32.CloseHandle(handle)

    return {
        "disk_number": disk["number"],
        "device_name": disk["name"],
        "bytes_overwritten": int(disk["size_bytes"]),
        "host_lba_readback_verified": True,
        "media_type": str(disk.get("media_type") or "Unknown"),
        "method": "logical zero overwrite with full host-LBA read-back",
        "performance": performance,
        "secure_sanitization": False,
        "assurance": "Lower-assurance logical overwrite; controller-managed, remapped, cache, and overprovisioned areas are not verified.",
    }


def overwrite_removable_disk(
    drive_letter: str,
    expected_fingerprint: str,
    typed_confirmation: str,
    progress: Callable[[str, int, int], None] | None = None,
) -> dict[str, Any]:
    """Backward-compatible alias for the external-disk operation."""
    return overwrite_external_disk(drive_letter, expected_fingerprint, typed_confirmation, progress)
