# c:\Users\ROG\Downloads\SDWTIAR Final\SDWTIAR\backend\app\routers\certificate.py
"""Certificate generation endpoint.

The endpoint receives a JSON payload describing the sanitisation job and
returns a PDF file that can be displayed in‑browser or downloaded.
"""

from __future__ import annotations

import io
from datetime import datetime
from typing import List

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

# ReportLab is a pure‑Python PDF library. Install with `pip install reportlab`
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.pdfgen import canvas

router = APIRouter(prefix="/certificate", tags=["Certificate"])


class CertificateRequest(BaseModel):
    """Data required to render the sanitisation certificate."""

    company_name: str = Field(..., description="Name of the company issuing the certificate")
    devices: List[str] = Field(..., description="List of device identifiers that have undergone sanitisation")
    timestamp: datetime | None = Field(
        default=None,
        description="When the sanitisation took place (ISO‑8601). If omitted the server time is used.",
    )
    signature_image: str | None = Field(
        default=None,
        description="Base64‑encoded PNG/JPEG of a digital signature; rendered if supplied.",
    )


def _draw_certificate(buf: io.BytesIO, data: CertificateRequest) -> None:
    """Render the PDF into *buf*.

    Layout:
    • double border (gold outer, dark inner)
    • centred headings
    • bullet list of devices
    • timestamp line
    • optional signature image or blank line for manual signing
    """
    page_w, page_h = landscape(letter)
    c = canvas.Canvas(buf, pagesize=(page_w, page_h))

    # Background & borders
    c.setFillColor(colors.HexColor("#FAFAF5"))
    c.rect(0, 0, page_w, page_h, fill=1, stroke=0)
    c.setStrokeColor(colors.HexColor("#D4AF37"))
    c.setLineWidth(4)
    c.rect(30, 30, page_w - 60, page_h - 60)
    c.setStrokeColor(colors.HexColor("#2C3E50"))
    c.setLineWidth(1)
    c.rect(38, 38, page_w - 76, page_h - 76)

    # Header
    c.setFillColor(colors.HexColor("#2C3E50"))
    c.setFont("Helvetica-Bold", 28)
    c.drawCentredString(page_w / 2, page_h - 90, "CERTIFICATE OF SANITISATION")

    # Company name
    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(page_w / 2, page_h - 130, data.company_name)

    # Subtitle
    c.setFont("Helvetica", 12)
    c.setFillColor(colors.HexColor("#7F8C8D"))
    c.drawCentredString(page_w / 2, page_h - 155, "This certifies that the following devices have been securely sanitised")

    # Device list
    c.setFillColor(colors.HexColor("#34495E"))
    c.setFont("Helvetica", 14)
    start_y = page_h - 190
    line_gap = 22
    for idx, dev in enumerate(data.devices, start=1):
        c.drawString(120, start_y - idx * line_gap, f"• {dev}")

    # Timestamp
    ts = (data.timestamp or datetime.utcnow()).strftime("%B %d, %Y – %H:%M %Z")
    c.setFont("Helvetica-Oblique", 12)
    c.drawCentredString(page_w / 2, 120, f"Sanitisation performed on: {ts}")

    # Signature line or image
    line_y = 80
    c.setStrokeColor(colors.HexColor("#7F8C8D"))
    c.setLineWidth(1)
    c.line(page_w / 2 - 200, line_y, page_w / 2 + 200, line_y)
    c.setFont("Helvetica-Bold", 11)
    c.drawCentredString(page_w / 2, line_y - 18, "Authorized Digital Signature")

    if data.signature_image:
        import base64
        try:
            img_bytes = base64.b64decode(data.signature_image)
            img = io.BytesIO(img_bytes)
            c.drawImage(
                img,
                page_w / 2 - 100,
                line_y + 10,
                width=200,
                preserveAspectRatio=True,
                mask="auto",
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid signature image: {exc}") from exc

    c.showPage()
    c.save()


@router.post(
    "/generate",
    summary="Generate a sanitisation certificate (PDF)",
    response_description="Streaming PDF file",
)
def generate_certificate(payload: CertificateRequest):
    """Create a PDF and stream it back.

    The client can open the returned URL in a browser (inline view) or
    download the file to the host device.
    """
    pdf_buffer = io.BytesIO()
    _draw_certificate(pdf_buffer, payload)
    pdf_buffer.seek(0)

    safe_company = "".join(c for c in payload.company_name if c.isalnum() or c in (" ", "_"))
    filename = f"{safe_company}_Sanitisation_{datetime.utcnow():%Y%m%d%H%M%S}.pdf"
    headers = {"Content-Disposition": f'inline; filename="{filename}"'}
    return StreamingResponse(pdf_buffer, media_type="application/pdf", headers=headers)

