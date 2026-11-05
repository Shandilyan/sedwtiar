"""Portable signed-certificate representations for download and verification."""

from __future__ import annotations

from io import BytesIO
from typing import Any

import qrcode
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.models import TamperEvidentCertificate


def certificate_export_document(
    certificate: TamperEvidentCertificate, verification_url: str, verification_status: dict[str, Any]
) -> dict[str, Any]:
    """Return metadata only; original user data is never included in an export."""
    verification = certificate.verification
    record = verification.sanitization_record
    asset = record.asset
    return {
        "document_type": "SEDWTIAR signed sanitization certificate",
        "document_version": "v2",
        "verification_url": verification_url,
        "certificate": {
            "id": certificate.id,
            "number": certificate.certificate_number,
            "version": certificate.certificate_version,
            "issuer": certificate.issuer,
            "issued_at": certificate.issued_at.isoformat(),
            "certificate_hash": certificate.certificate_hash,
            "previous_certificate_hash": certificate.previous_certificate_hash,
            "signature": certificate.signature,
            "signature_algorithm": certificate.signature_algorithm,
            "signing_key_id": certificate.signing_key_id,
            "public_key": certificate.public_key,
        },
        "asset": {
            "asset_id": asset.id,
            "asset_tag": asset.asset_tag,
            "manufacturer": asset.manufacturer,
            "model": asset.model,
            "serial_number": asset.serial_number,
            "storage_type": asset.storage_type,
            "storage_capacity_gb": asset.storage_capacity_gb,
        },
        "sanitization_evidence": {
            "record_id": record.id,
            "method": record.method,
            "evidence_hash": record.evidence_hash,
            "record_status": record.status.value,
        },
        "independent_verification": {
            "id": verification.id,
            "outcome": verification.outcome.value,
            "method": verification.verification_method,
            "verifier": verification.verifier_name,
            "verified_at": verification.verified_at.isoformat(),
            "evidence_hash": verification.evidence_hash,
        },
        "signature_check": verification_status,
        "disclosure": (
            "This certificate documents recorded sanitization evidence and the stated verification result. "
            "It does not itself prove a media method beyond the method and evidence recorded here."
        ),
    }


def certificate_pdf_bytes(document: dict[str, Any]) -> bytes:
    """Render a concise, on-screen equivalent PDF certificate with verification QR code."""
    output = BytesIO()
    styles = getSampleStyleSheet()
    body = styles["BodyText"]
    body.fontName = "Helvetica"
    body.fontSize = 8.5
    body.leading = 11
    title = styles["Title"]
    title.textColor = colors.HexColor("#123A5A")
    story = [Paragraph("SEDWTIAR - Signed Sanitization Certificate", title)]
    story.append(Paragraph("Cryptographic integrity record - Ed25519 development signer", styles["Heading3"]))
    story.append(Spacer(1, 4 * mm))

    certificate = document["certificate"]
    asset = document["asset"]
    evidence = document["sanitization_evidence"]
    verification = document["independent_verification"]
    status = document["signature_check"]
    rows = [
        ["Certificate", certificate["number"]],
        ["Status", status["status"]],
        ["Asset", asset["asset_tag"]],
        ["Device", " ".join(item for item in (asset.get("manufacturer"), asset.get("model")) if item) or "Not recorded"],
        ["Storage", " ".join(item for item in (asset.get("storage_type"), f"{asset['storage_capacity_gb']} GB" if asset.get("storage_capacity_gb") else None) if item) or "Not recorded"],
        ["Sanitization method", evidence["method"]],
        ["Verification", f"{verification['outcome']} - {verification['method']}"],
        ["Verified at", verification["verified_at"]],
        ["Signer", f"{certificate.get('signature_algorithm') or 'None'} / {certificate.get('signing_key_id') or 'Not recorded'}"],
    ]
    table = Table(
        [[Paragraph(str(left), body), Paragraph(str(right), body)] for left, right in rows],
        colWidths=(47 * mm, 125 * mm),
        repeatRows=0,
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF1F6")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9FB3C8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([table, Spacer(1, 5 * mm)])
    hashes = [
        ["Evidence SHA-256", evidence.get("evidence_hash") or "Not recorded"],
        ["Certificate SHA-256", certificate["certificate_hash"]],
        ["Previous certificate hash", certificate.get("previous_certificate_hash") or "None (first record)"],
    ]
    hash_table = Table(
        [[Paragraph(str(left), body), Paragraph(str(right), body)] for left, right in hashes],
        colWidths=(47 * mm, 125 * mm),
    )
    hash_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8F3E6")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#B89A55")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([hash_table, Spacer(1, 4 * mm)])
    qr_buffer = BytesIO()
    qrcode.make(document["verification_url"]).save(qr_buffer, format="PNG")
    qr_buffer.seek(0)
    story.append(Image(qr_buffer, width=32 * mm, height=32 * mm))
    story.append(Paragraph(f"Verify certificate: {document['verification_url']}", body))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(document["disclosure"], body))
    SimpleDocTemplate(
        output, pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm
    ).build(story)
    return output.getvalue()
