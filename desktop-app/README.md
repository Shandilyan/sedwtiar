# SEDWTIAR Desktop

Native Windows desktop client built with Python and PySide6. It connects to the
existing FastAPI/PostgreSQL service at `http://127.0.0.1:8000` and to a local
Ollama service at `http://127.0.0.1:11434` for the Gemma assistant.

The Connected Devices page reads the host's Windows storage inventory and
refreshes periodically. It labels Windows boot/system disks as protected, and
lists optical drives as inventory only. Gemma is advisory and cannot choose or
start a storage operation. File review can preview selected hidden files and
perform best-effort zero-overwrite/read-back before unlinking them. A separate, explicit whole-device zero
overwrite is available for a revalidated externally attached disk; it is lower-assurance
and must not be represented as verified sanitization.

## Performance behaviour

- Dashboard and asset-workflow snapshots load on a background Qt worker, so
  navigation remains usable while PostgreSQL-backed data is refreshing.
- Windows device inventory runs on demand and every 60 seconds while the app is
  open, rather than repeatedly interrupting the interface at a short interval.
- The external-device overwrite path reuses its read-back buffer. It uses a
  bounded 16 MiB sequential buffer by default and 32 MiB when Windows
  identifies the external medium as an SSD. This lowers call/allocation
  overhead without removing the full host-LBA read-back check.
- Progress is refreshed up to four times per second, including inside a single
  percentage point. This is particularly important for a 2 TB external SSD.

Actual throughput depends on the Seagate SSD model, enclosure, cable, USB port,
Windows driver, and drive condition. The app deliberately keeps a complete
read-back verification pass, so a full 2 TB logical overwrite necessarily
includes both a write pass and a read pass.

The File Type Review page can be explicitly run against an eligible detected
external USB/SD/MMC/1394 volume. It counts extensions and sizes without reading file contents,
and sends only those aggregate counts to the local Gemma runtime. Recommendations
explain that extensions are hints and that individual-file deletion is not a
reliable whole-media sanitization method.

## Setup

From this directory in PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

For the recommended guarded launcher, use:

```powershell
cd E:\SDWTIAR\desktop-app
& .\start-desktop.ps1
```

The launcher uses the desktop virtual environment, starts the local backend
when required, and reports a non-zero exit code instead of silently closing.
The desktop keeps a rotating local diagnostic log at
`%LOCALAPPDATA%\SEDWTIAR\logs\desktop.log`; automatic backend launch output is
recorded beside it as `backend.log`.

The desktop app automatically starts the sibling FastAPI backend when the
default local API (`http://127.0.0.1:8000`) is unavailable. To run it manually:

```powershell
cd ..\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Install Ollama for Windows, then pull a small local Gemma model:

```powershell
ollama pull gemma3:1b
```

Ollama normally runs in the Windows tray after installation. If its local API
is unavailable, open another PowerShell window and start it with:

```powershell
ollama serve
```

The file-review page uses the local Ollama `/api/chat` endpoint and defaults to
`gemma3:1b`. Set `SEDWTIAR_OLLAMA_MODEL` to select another locally installed
model. The app sends only file-type aggregate counts to that local model; it
does not send prompts or file metadata to a cloud model.

## Physical-device scope and limitations

- Windows first; the current inventory adapter uses Windows Storage Management.
- USB/removable media, USB-attached HDDs/SSDs, and optical drives can be detected and shown.
- Internal HDD/SSD/NVMe disks are inventory-only, even if they are not currently
  marked boot/system. This is a deliberate protection against selecting a host disk.
- Ordinary CD-ROM/CD-R is not erasable; optical media is not currently a
  sanitization target.
- The optional **Overwrite entire external disk — lower assurance** operation writes
  zeroes to all host-addressable blocks of the selected physical disk and reads
  those blocks back. It requires a warning acknowledgement and an exact typed
  disk/size phrase, then revalidates the disk and locks its mounted volumes.
- This is not a verified secure-sanitization method. USB flash controllers can
  remap blocks or reserve overprovisioned areas; a host-level zero write and
  read-back cannot prove those areas were erased. Use a device-supported
  sanitize/secure-erase function with documented validation for a real
  disposal claim. The optional overwrite may still permanently destroy every
  partition on the selected disk.
- The app never starts a physical overwrite automatically. Do not run it on a
  disk containing anything you need. Running it requires suitable Windows
  permissions and a stable external-drive connection.
- The existing simulation is clearly separated as a legacy demo and must never
  be described as physical sanitization.

## File-type review

1. Connect an external USB flash drive, USB-attached HDD, or USB-attached SSD.
2. Open **Connected Devices** and let the inventory refresh.
3. Open **File Type Review**, choose an eligible external volume, then select
   **Scan file-type metadata and ask Gemma**.
4. Review the extension categories and the local advisory recommendation.

This scan is read-only. It never reads file contents or keeps file names. A
type/extension match is only a hint, not content classification or proof of
secure deletion. Windows System-marked items are reported separately and are
not offered for pruning.

**Preview / prune hidden files** lists hidden non-System files first and asks
for confirmation. It zero-overwrites and reads back each selected file's
current logical contents before unlinking it. This is best-effort only and
does not guarantee recovery is impossible: USB flash remapping,
overprovisioning, filesystem journals/copies, and device caches are not
verified. Windows System-marked files are excluded. The app no longer has a
control for adding demo files to the drive.

## Legacy demo path

1. Open the Overview and choose **Create Demo Asset** or register an asset.
2. Select it in Workflow and record **Demo Inspection** values.
3. Read the deterministic method recommendation.
4. Start **Controlled Sanitization Simulation**.
5. Run the separate evidence verification; proceed only after PASS.
6. Generate the integrity certificate and reuse disposition.
7. Review its records in Evidence & Timeline.

Use **Refresh** on Overview to reload current PostgreSQL-backed counts and
activity. Completing workflow actions refreshes those dashboard values too.

Every legacy simulated step is labelled in the UI. Live device enumeration and
file-type metadata review are read-only. File pruning and whole-disk overwrite
are separate actions with their own warnings and confirmations; neither is
described as verified sanitization.
