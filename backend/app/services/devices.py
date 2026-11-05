"""Read-only Windows storage inventory service for SEDWTIAR backend."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from typing import Any


class DeviceInventoryError(RuntimeError):
    """Raised when Windows cannot provide a trustworthy read-only inventory."""


EXTERNAL_BUS_TYPES = frozenset({"usb", "sd", "mmc", "1394"})

_POWERSHELL_INVENTORY = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$physical = @()
if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
    $physical = @(Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
            friendly_name = [string]$_.FriendlyName
            serial_number = [string]$_.SerialNumber
            size_bytes = [long]$_.Size
            media_type = [string]$_.MediaType
            health_status = [string]$_.HealthStatus
        }
    })
}
$disks = @(Get-Disk | ForEach-Object {
    $disk = $_
    $match = @($physical | Where-Object {
        ($_.serial_number -and $disk.SerialNumber -and $_.serial_number -eq [string]$disk.SerialNumber) -or
        ($_.friendly_name -and $_.friendly_name -eq [string]$disk.FriendlyName -and $_.size_bytes -eq [long]$disk.Size)
    } | Select-Object -First 1)
    $physicalMatch = if ($match.Count -gt 0) { $match[0] } else { $null }
    $parts = @(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue |
        Select-Object @{n='drive_letter';e={$_.DriveLetter}}, @{n='type';e={[string]$_.Type}},
            @{n='is_boot';e={[bool]$_.IsBoot}}, @{n='is_system';e={[bool]$_.IsSystem}})
    [pscustomobject]@{
        number = [int]$disk.Number
        name = [string]$disk.FriendlyName
        bus_type = [string]$disk.BusType
        serial_number = [string]$disk.SerialNumber
        unique_id = [string]$disk.UniqueId
        size_bytes = [long]$disk.Size
        status = [string]($disk.OperationalStatus -join ', ')
        is_system = [bool]$disk.IsSystem
        is_boot = [bool]$disk.IsBoot
        is_read_only = [bool]$disk.IsReadOnly
        is_offline = [bool]$disk.IsOffline
        media_type = if ($physicalMatch) { [string]$physicalMatch.media_type } else { 'Unspecified' }
        health_status = if ($physicalMatch) { [string]$physicalMatch.health_status } else { 'Unknown' }
        partitions = $parts
    }
})
$optical = @(Get-CimInstance Win32_CDROMDrive -ErrorAction SilentlyContinue |
    Select-Object @{n='name';e={$_.Name}}, @{n='drive';e={$_.Drive}},
        @{n='media_loaded';e={[bool]$_.MediaLoaded}}, @{n='status';e={$_.Status}})
[pscustomobject]@{ disks = $disks; optical_drives = $optical } |
    ConvertTo-Json -Depth 6 -Compress
"""


def _as_list(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return [value] if isinstance(value, dict) else []


def get_storage_inventory(timeout_seconds: int = 15) -> dict[str, Any]:
    """Return live connected disks and optical drives on Windows."""
    if os.name != "nt":
        return {
            "disks": [
                {
                    "number": 0,
                    "name": "Simulated Primary NVMe",
                    "bus_type": "NVMe",
                    "size_bytes": 1024209543168,
                    "status": "Online",
                    "media_type": "SSD",
                    "health_status": "Healthy",
                    "is_read_only": False,
                    "is_offline": False,
                    "protected": True,
                    "fingerprint": "74E7DF378B4F",
                    "partitions": [{"drive_letter": "C", "type": "Basic"}],
                    "external_attached": False,
                    "connection": "Internal / fixed bus",
                    "execution_eligibility": "Blocked - boot/system disk",
                }
            ],
            "optical_drives": [],
        }

    try:
        result = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _POWERSHELL_INVENTORY],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DeviceInventoryError(f"Windows storage inventory could not run: {exc}") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"PowerShell exit code {result.returncode}"
        raise DeviceInventoryError(f"Windows storage inventory failed: {detail}")

    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DeviceInventoryError("Windows returned invalid storage inventory data.") from exc

    disks = []
    for disk in _as_list(raw.get("disks")):
        parts = _as_list(disk.get("partitions"))
        protected = (
            disk.get("is_system") is True
            or disk.get("is_boot") is True
            or any(part.get("is_system") is True or part.get("is_boot") is True for part in parts)
        )
        unique_material = "|".join((
            str(disk.get("serial_number") or ""),
            str(disk.get("unique_id") or ""),
            str(disk.get("name") or ""),
        ))
        fingerprint = hashlib.sha256(unique_material.encode("utf-8")).hexdigest()[:12].upper()
        partitions = [
            {
                "drive_letter": part.get("drive_letter"),
                "type": part.get("type"),
            }
            for part in parts
        ]
        bus_type = str(disk.get("bus_type") or "Unknown")
        external_attached = bus_type.casefold() in EXTERNAL_BUS_TYPES
        media_type = str(disk.get("media_type") or "Unspecified")
        if media_type.casefold() in {"", "unspecified", "unknown"}:
            media_type = "Unknown"
        disks.append({
            "number": disk.get("number"),
            "name": str(disk.get("name") or "Unidentified disk"),
            "bus_type": bus_type,
            "size_bytes": int(disk.get("size_bytes") or 0),
            "status": str(disk.get("status") or "Unknown"),
            "media_type": media_type,
            "health_status": str(disk.get("health_status") or "Unknown"),
            "is_read_only": disk.get("is_read_only") is True,
            "is_offline": disk.get("is_offline") is True,
            "protected": protected,
            "fingerprint": fingerprint,
            "partitions": partitions,
            "external_attached": external_attached,
            "connection": "External / removable bus" if external_attached else "Internal / fixed bus",
            "execution_eligibility": (
                "Blocked - boot/system disk" if protected else
                "Blocked - Windows reports read-only/offline" if disk.get("is_read_only") is True or disk.get("is_offline") is True else
                "External target - explicit confirmation required" if external_attached else
                "Inventory only - internal/fixed disk"
            ),
        })

    optical = [
        {
            "name": str(device.get("name") or "Optical drive"),
            "drive": str(device.get("drive") or "No drive letter"),
            "media_loaded": device.get("media_loaded") is True,
            "status": str(device.get("status") or "Unknown"),
            "sanitization_supported": False,
        }
        for device in _as_list(raw.get("optical_drives"))
    ]
    return {"disks": disks, "optical_drives": optical}
