"""Pydantic contracts for tamper-evident certificate metadata."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class TamperEvidentCertificateCreate(BaseModel):
    certificate_number: str = Field(min_length=1, max_length=100)
    issuer: str = Field(min_length=1, max_length=150)
    payload_hash: str = Field(min_length=1, max_length=255)
    hash_algorithm: str = Field(default="sha256", min_length=1, max_length=50)
    issued_at: datetime


class TamperEvidentCertificateRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    verification_id: str
    certificate_number: str
    issuer: str
    payload_hash: str
    hash_algorithm: str
    certificate_hash: str
    previous_certificate_hash: Optional[str]
    certificate_version: str
    signature: Optional[str]
    signature_algorithm: Optional[str]
    signing_key_id: Optional[str]
    public_key: Optional[str]
    issued_at: datetime
    created_at: datetime


class CertificateVerificationRead(BaseModel):
    certificate_id: str
    certificate_number: str
    certificate_version: str
    integrity_hash_valid: bool
    signature_valid: bool
    locally_trusted_signing_key: bool
    status: str
    detail: str
