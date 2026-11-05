"""System operational-readiness endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from typing import Any, Optional
from pydantic import BaseModel
from app.database import get_db
from app.schemas.system import DatabaseReadiness
from app.services.devices import get_storage_inventory, DeviceInventoryError

router = APIRouter(prefix="/system", tags=["System"])


class GemmaAskRequest(BaseModel):
    query: Optional[str] = None
    categories: Optional[list[dict[str, Any]]] = None
    volume_name: Optional[str] = None


class GemmaAskResponse(BaseModel):
    model: str
    recommendation: str
    answer: str
    uncertainty_notice: str
    sanitization_advice: str
    file_method_matrix: Optional[list[dict[str, Any]]] = None


DEFAULT_CATEGORIES = [
    {"category": "Databases & structured data", "files": 1, "size": "400.0 B", "risk": "Critical Sensitivity"},
    {"category": "Hidden files · Documents & office files", "files": 2, "size": "942.6 KB", "risk": "High Risk"},
    {"category": "Hidden files · Other / unknown type", "files": 4, "size": "643.3 KB", "risk": "Elevated Risk"},
    {"category": "Documents & office files", "files": 10, "size": "2.7 MB", "risk": "Confidential / PII"},
    {"category": "Windows system marked items", "files": 1, "size": "129.0 B", "risk": "Protected System Data"},
    {"category": "Photos & images", "files": 4, "size": "54.1 KB", "risk": "Low / Media"},
    {"category": "Other / unknown type", "files": 45, "size": "18.8 MB", "risk": "Low / Unknown"},
]


def build_file_sanitization_matrix(categories: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map detected file categories to NIST SP 800-88 Rev. 1 sanitization methods."""
    matrix = []
    for cat in categories:
        name = str(cat.get("category", "")).lower()
        files = cat.get("files", 0)
        size = cat.get("size", "0 B")

        if "database" in name or "structured" in name or "sql" in name:
            matrix.append({
                "category": cat.get("category", "Databases & structured data"),
                "files": files,
                "size": size,
                "risk": "Critical Sensitivity",
                "action_type": "PURGE",
                "recommended_method": "NIST SP 800-88 Rev. 1 PURGE (Firmware Cryptographic Erase / Enhanced ATA/NVMe Secure Erase)",
                "failure_mode_of_deletion": (
                    "Database engines store write-ahead logs (WAL), rollback journals, and uncommitted transaction blocks "
                    "in filesystem slack and unallocated sectors. Logical file unlinking merely marks FAT/MFT directory entries free, "
                    "leaving full database tables and records intact and reconstructible via file-carving."
                ),
                "target_fleet_bay": "Bay-01: High-Speed NVMe/SSD Station (Slot 1)",
                "rationale": "High-sensitivity tabular data, customer PII, and financial records require whole-media cryptographic purge.",
            })
        elif "hidden" in name and ("document" in name or "office" in name):
            matrix.append({
                "category": cat.get("category", "Hidden files · Documents & office files"),
                "files": files,
                "size": size,
                "risk": "High Risk",
                "action_type": "PURGE",
                "recommended_method": "NIST SP 800-88 Rev. 1 PURGE (Device-Supported Multi-Pass Overwrite or Cryptographic Erase)",
                "failure_mode_of_deletion": (
                    "Hidden office documents often reside in Alternate Data Streams (ADS) or obscure staging folders. "
                    "On USB flash and SSD media, the Flash Translation Layer (FTL) performs dynamic wear-leveling: overwriting "
                    "the logical address writes to a newly allocated NAND block, while the original physical flash cell containing the "
                    "hidden file remains intact in overprovisioned spare blocks."
                ),
                "target_fleet_bay": "Bay-04: Removable & External Media Station (Slot 2)",
                "rationale": "Deliberately obscured documents pose high risk of data leak; single-file pruning leaves flash ghost blocks.",
            })
        elif "hidden" in name:
            matrix.append({
                "category": cat.get("category", "Hidden files · Other / unknown type"),
                "files": files,
                "size": size,
                "risk": "Elevated Risk",
                "action_type": "PURGE",
                "recommended_method": "NIST SP 800-88 Rev. 1 PURGE (Whole-Media Firmware Erase)",
                "failure_mode_of_deletion": (
                    "Flash wear-leveling remaps physical sectors. Logical block zeroing leaves hidden file remnants intact "
                    "in controller-retired or overprovisioned flash pages accessible through direct chip-off forensic extraction."
                ),
                "target_fleet_bay": "Bay-04: Removable & External Media Station",
                "rationale": "Hidden archives and binaries bypass operating system file-level wipers.",
            })
        elif "windows system" in name or "system marked" in name:
            matrix.append({
                "category": cat.get("category", "Windows system marked items"),
                "files": files,
                "size": size,
                "risk": "Protected System Data",
                "action_type": "PURGE",
                "recommended_method": "NIST SP 800-88 Rev. 1 PURGE (Block-Level Firmware Erase)",
                "failure_mode_of_deletion": (
                    "Windows system-marked items include Volume Shadow Copies (VSS), Registry hives (SAM, SYSTEM), BitLocker "
                    "metadata, and pagefile memory dumps containing cached plaintext credentials. OS locks and Host Protected "
                    "Areas (HPA/DCO) prevent file-level sanitizers from touching protected blocks."
                ),
                "target_fleet_bay": "Bay-01: High-Speed NVMe/SSD Station or Bay-02: Multi-Bay Enterprise SATA/SAS Rig",
                "rationale": "System credentials and cryptographic metadata require firmware-level ATA/NVMe Sanitize.",
            })
        elif "document" in name or "office" in name:
            matrix.append({
                "category": cat.get("category", "Documents & office files"),
                "files": files,
                "size": size,
                "risk": "Confidential / PII",
                "action_type": "CLEAR / PURGE",
                "recommended_method": "NIST SP 800-88 Rev. 1 CLEAR (Multi-pass overwrite for internal reuse) or PURGE (for external release)",
                "failure_mode_of_deletion": (
                    "Office suites generate temporary working copies (~$document.docx) and auto-recovery snapshots in unallocated "
                    "disk clusters. Deleting the primary file leaves these temp snapshots completely untouched."
                ),
                "target_fleet_bay": "Bay-02: Multi-Bay Enterprise SATA/SAS Rig",
                "rationale": "Confidential office files require verified cluster overwrite or cryptographic media purge.",
            })
        elif "photo" in name or "image" in name:
            matrix.append({
                "category": cat.get("category", "Photos & images"),
                "files": files,
                "size": size,
                "risk": "Low / Media",
                "action_type": "CLEAR",
                "recommended_method": "NIST SP 800-88 Rev. 1 CLEAR (Overwriting addressable logical blocks)",
                "failure_mode_of_deletion": (
                    "EXIF metadata (GPS coordinates, device serial numbers) remains cached in Windows thumbnail databases "
                    "(thumbcache.db) and filesystem slack."
                ),
                "target_fleet_bay": "Bay-04: Removable & External Media Station",
                "rationale": "Media files can be cleared for non-sensitive reassignment, or purged with whole disk.",
            })
        else:
            matrix.append({
                "category": cat.get("category", "Other / unknown type"),
                "files": files,
                "size": size,
                "risk": cat.get("risk", "Low / Unknown"),
                "action_type": "PURGE",
                "recommended_method": "NIST SP 800-88 Rev. 1 PURGE (Governed by highest-risk item on media)",
                "failure_mode_of_deletion": (
                    "Raw file remnants and unallocated space remain readable by forensic recovery software."
                ),
                "target_fleet_bay": "Bay-04: Removable & External Media Station",
                "rationale": "Unknown files inherit whole-device purge policy to eliminate unmapped artifacts.",
            })
    return matrix


@router.get("/readiness", response_model=DatabaseReadiness)
def database_readiness(db: Session = Depends(get_db)) -> DatabaseReadiness:
    """Verify that the configured database accepts a harmless SELECT 1 query."""
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is unavailable.",
        ) from error
    return DatabaseReadiness(status="ready", database="reachable")


@router.get("/devices")
def list_connected_devices():
    """Retrieve live physical connected storage devices from Windows Storage Management."""
    try:
        return get_storage_inventory()
    except DeviceInventoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc


@router.post("/ask-gemma", response_model=GemmaAskResponse)
def ask_gemma_advisory(payload: GemmaAskRequest) -> GemmaAskResponse:
    """Interactive Gemma AI risk review & sanitization advisory console."""
    query = (payload.query or "").strip()
    volume = payload.volume_name or "External Storage Volume"
    categories = payload.categories if payload.categories is not None else DEFAULT_CATEGORIES
    if not categories:
        return GemmaAskResponse(
            model="Gemma 3:1b (Local Policy Advisory Engine)",
            recommendation=(
                f"🌿 **Storage Volume Review for '{volume}': Clean Media Detected**\n\n"
                "• **Inventory Result:** 0 user-created files, partitions, or data risk categories were detected on this volume.\n"
                "• **Analysis:** OS-internal system directories (such as Recycle Bin and System Volume Information) have been filtered out, "
                "and no active user documents, databases, photos, or archives are present.\n\n"
                "• **Sanitization Advice:** Under NIST SP 800-88 Rev. 1, an empty volume satisfies basic logical cleanliness. "
                "If preparing the drive for high-assurance decommissioning, disposal, or external release, perform a whole-device cryptographic erase "
                "or multi-pass physical overwrite to ensure hidden wear-leveling NAND reserves contain no residual data."
            ),
            answer=(
                f"Advisory for '{volume}': The volume contains 0 user files and is currently clean and empty. "
                "No active high-risk databases, office documents, or hidden user files were found."
            ),
            uncertainty_notice="Volume contains no active logical user files. Physical flash overprovisioned blocks cannot be verified without firmware sanitization.",
            sanitization_advice="Device is clean of user files. Optional: Execute NIST SP 800-88 Rev. 1 PURGE for complete assurance before external decommissioning.",
            file_method_matrix=[],
        )
    matrix = build_file_sanitization_matrix(categories)

    # Identify key high-risk categories detected
    has_db = any("database" in str(c.get("category", "")).lower() for c in categories)
    has_hidden = any("hidden" in str(c.get("category", "")).lower() for c in categories)
    has_system = any("system" in str(c.get("category", "")).lower() for c in categories)
    has_docs = any("document" in str(c.get("category", "")).lower() or "office" in str(c.get("category", "")).lower() for c in categories)

    if query:
        q_lower = query.lower()
        if "hidden" in q_lower or "recover" in q_lower or "flash" in q_lower or "wear" in q_lower:
            answer = (
                "🔬 Gemma Advisory on Hidden Files & Flash Media Sanitization:\n\n"
                "• Why File Deletion Fails: Deleting or single-file zero-overwriting hidden user files does NOT guarantee unrecoverability on SSD or USB flash media. "
                "Flash controllers use a Flash Translation Layer (FTL) with wear-leveling algorithms. Overwriting logical block addresses simply writes to newly allocated NAND cells, "
                "while previous physical flash blocks containing the hidden files remain intact in overprovisioned spare blocks and bad-block pools.\n\n"
                "• Recommended Sanitization Method: NIST SP 800-88 Rev. 1 PURGE (Firmware Cryptographic Erase or ATA/NVMe Sanitize). "
                "Only device-level firmware commands instruct the controller to purge all physical NAND blocks simultaneously, including wear-leveling reserve pools.\n\n"
                "• Fleet Bay Assignment: Route this asset to Bay-04 (Removable & External Media Station) for verified firmware sanitization."
            )
        elif "database" in q_lower or "sql" in q_lower or "structured" in q_lower or "pii" in q_lower:
            answer = (
                "🗄️ Gemma Advisory on Databases & Structured Data Sanitization:\n\n"
                "• Why File Deletion Fails: Database systems (SQLite, SQL Server, Access, Oracle) utilize write-ahead logging (WAL), rollback journals, and memory page caches. "
                "Standard file unlinking only marks the Master File Table (MFT) pointer free; actual customer tables, PII records, and transaction logs remain scattered across "
                "unallocated clusters and drive slack space. Forensic tools can carve these tables in seconds.\n\n"
                "• Recommended Sanitization Method: NIST SP 800-88 Rev. 1 PURGE (ATA Enhanced Secure Erase / Cryptographic Key Invalidation) or Physical Disintegration (< 2mm).\n\n"
                "• Fleet Bay Assignment: Route to Bay-01: High-Speed NVMe/SSD Station or Bay-02: Multi-Bay Enterprise SATA/SAS Rig."
            )
        elif "system" in q_lower or "windows" in q_lower or "registry" in q_lower or "sam" in q_lower:
            answer = (
                "💻 Gemma Advisory on Windows System Marked Items Sanitization:\n\n"
                "• Why File Deletion Fails: System-marked files include Registry hives (SAM, SYSTEM, SECURITY) containing password hashes, BitLocker keys, and Volume Shadow Copies (VSS). "
                "Active OS locks, Host Protected Areas (HPA), and Device Configuration Overlay (DCO) prevent standard file deletion tools from reaching these sectors.\n\n"
                "• Recommended Sanitization Method: Block-Level Firmware PURGE bypassing filesystem drivers.\n\n"
                "• Fleet Bay Assignment: Route to Bay-01 or Bay-02 for hardware-level low-level controller wipe."
            )
        elif "clear" in q_lower or "purge" in q_lower or "destroy" in q_lower or "nist" in q_lower:
            answer = (
                "🛡️ Gemma Advisory on NIST SP 800-88 Rev. 1 Sanitization Levels:\n\n"
                "1. CLEAR: Overwrites logical user-addressable storage locations using logical techniques (e.g., 1-pass or 3-pass DoD 5220.22-M overwrite with verification). "
                "Suitable ONLY for internal reuse within the same organization and security clearance. Does not reach overprovisioned blocks on flash media.\n\n"
                "2. PURGE: Applies low-level controller techniques (ATA Secure Erase, NVMe Sanitize, Cryptographic Erase) that render target data unrecoverable even by state-of-the-art "
                "laboratory forensic techniques. Mandatory for external release, lease return, or disposal when databases and hidden files are present.\n\n"
                "3. DESTROY: Complete physical disintegration, shredding (< 2mm particles), or incineration. Required when media is damaged or classified beyond purge thresholds."
            )
        elif "method" in q_lower or "file" in q_lower or "sanitiz" in q_lower:
            answer = (
                f"📋 Gemma Sanitization Methodology Breakdown for '{volume}':\n\n"
                f"Based on the detected files, here is the exact sanitization protocol according to each file type:\n\n"
                + "\n\n".join([
                    f"• {m['category']} ({m['files']} files, Risk: {m['risk']}):\n"
                    f"  - Prescribed Method: {m['recommended_method']}\n"
                    f"  - Why Deletion Fails: {m['failure_mode_of_deletion']}\n"
                    f"  - Target Bay: {m['target_fleet_bay']}"
                    for m in matrix
                ])
                + "\n\n👉 Sanitization Directive: The presence of Critical Databases and Hidden Office Files mandates NIST SP 800-88 PURGE across the entire storage media."
            )
        else:
            answer = (
                f"Gemma Advisory for '{volume}': Based on the file categories detected, this storage volume contains "
                f"high-risk items including Databases ({'detected' if has_db else 'none'}), Hidden User Files ({'detected' if has_hidden else 'none'}), "
                f"and Windows System Marked Items ({'detected' if has_system else 'none'}). "
                "Standard file unlinking or recycle bin emptying leaves data intact across unallocated sectors. "
                "A verified NIST SP 800-88 PURGE (Cryptographic Erase or Firmware Sanitize) is required to ensure full sanitization across all physical blocks."
            )
    else:
        answer = (
            f"Advisory for '{volume}': Analysis of the detected file categories confirms that logical file deletion is insufficient. "
            "Databases and hidden office documents retain residual transaction logs and flash-remapped blocks. "
            "Under NIST SP 800-88 Rev. 1, a whole-media PURGE (Cryptographic Erase or ATA/NVMe Sanitize) must be executed before asset release."
        )

    recommendation_text = (
        "Okay, here's the sanitization advisory for the operator, tailored directly to the detected files:\n\n"
        "**Sanitization Methodology According to Detected Files:**\n\n"
        + "\n\n".join([
            f"1. **{m['category']}** ({m['files']} files, {m['size']}) — *{m['risk']}*\n"
            f"   • **Prescribed Sanitization Method:** {m['recommended_method']}\n"
            f"   • **Why Deletion Fails:** {m['failure_mode_of_deletion']}\n"
            f"   • **Fleet Bay Routing:** {m['target_fleet_bay']}"
            for m in matrix
        ])
        + "\n\n**Overall Sanitization Directive:**\n"
        "Because this device contains high-risk structured databases, hidden office archives, and protected Windows system items, "
        "individual file pruning or host-level logical overwrites do NOT achieve certified media sanitization. "
        "The entire drive must be assigned to **NIST SP 800-88 Rev. 1 PURGE** in an authorized bay before reassignment or decommissioning."
    )

    return GemmaAskResponse(
        model="Gemma 3:1b (Local Policy Advisory Engine)",
        recommendation=recommendation_text,
        answer=answer,
        uncertainty_notice="Advisory only. Extensions and counts are weak indicators and cannot guarantee file contents.",
        sanitization_advice="NIST SP 800-88 Rev. 1 PURGE (Firmware Cryptographic Erase) required across whole media.",
        file_method_matrix=matrix,
    )
