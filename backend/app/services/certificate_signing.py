"""Local development Ed25519 certificate signing.

The private key is created only when a new certificate is issued.  On Windows
it is protected with the current user's DPAPI profile and stored outside the
repository.  The key is never returned by the API, written to the database, or
placed in an environment file.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import os
from ctypes import wintypes
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class CertificateSigningError(RuntimeError):
    """Raised when the local certificate signer is unavailable or invalid."""


CRYPTPROTECT_UI_FORBIDDEN = 0x1


class _DataBlob(ctypes.Structure):
    _fields_ = (("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte)))


def _key_path() -> Path:
    override = os.getenv("SEDWTIAR_SIGNING_KEY_PATH")
    if override:
        return Path(override)
    local_app_data = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return local_app_data / "SEDWTIAR" / "keys" / "certificate-ed25519.dpapi"


def _blob(data: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_char]]:
    buffer = ctypes.create_string_buffer(data)
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def _protect_with_dpapi(data: bytes) -> bytes:
    if os.name != "nt":
        raise CertificateSigningError("Local development certificate signing currently requires Windows DPAPI.")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptProtectData.argtypes = (
        ctypes.POINTER(_DataBlob), wintypes.LPCWSTR, ctypes.POINTER(_DataBlob), wintypes.LPVOID,
        wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(_DataBlob),
    )
    crypt32.CryptProtectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = (wintypes.HLOCAL,)
    kernel32.LocalFree.restype = wintypes.HLOCAL
    source, source_buffer = _blob(data)
    output = _DataBlob()
    if not crypt32.CryptProtectData(
        ctypes.byref(source), "SEDWTIAR local Ed25519 certificate key", None, None, None,
        CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(output),
    ):
        raise CertificateSigningError(f"Windows DPAPI could not protect the signing key (WinError {ctypes.get_last_error()}).")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(output.pbData, wintypes.HLOCAL))
        del source_buffer


def _unprotect_with_dpapi(data: bytes) -> bytes:
    if os.name != "nt":
        raise CertificateSigningError("Local development certificate signing currently requires Windows DPAPI.")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptUnprotectData.argtypes = (
        ctypes.POINTER(_DataBlob), ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(_DataBlob),
        wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(_DataBlob),
    )
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = (wintypes.HLOCAL,)
    kernel32.LocalFree.restype = wintypes.HLOCAL
    source, source_buffer = _blob(data)
    output = _DataBlob()
    description = wintypes.LPWSTR()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(source), ctypes.byref(description), None, None, None,
        CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(output),
    ):
        raise CertificateSigningError(
            "Windows DPAPI could not open the local certificate signing key. "
            "Use the same Windows account that created it."
        )
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        if description:
            kernel32.LocalFree(ctypes.cast(description, wintypes.HLOCAL))
        kernel32.LocalFree(ctypes.cast(output.pbData, wintypes.HLOCAL))
        del source_buffer


def _load_or_create_private_key() -> Ed25519PrivateKey:
    path = _key_path()
    try:
        if path.exists():
            protected = path.read_bytes()
            private_bytes = _unprotect_with_dpapi(protected)
            key = serialization.load_pem_private_key(private_bytes, password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise CertificateSigningError("The local signing-key file is not an Ed25519 private key.")
            return key

        key = Ed25519PrivateKey.generate()
        private_bytes = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_bytes(_protect_with_dpapi(private_bytes))
        os.replace(temporary, path)
        return key
    except CertificateSigningError:
        raise
    except OSError as exc:
        raise CertificateSigningError(f"The local certificate signing key could not be accessed: {exc}") from exc
    except (TypeError, ValueError) as exc:
        raise CertificateSigningError("The local certificate signing key is invalid or corrupted.") from exc


def _message(certificate_hash: str) -> bytes:
    if len(certificate_hash) != 64 or any(character not in "0123456789abcdef" for character in certificate_hash.lower()):
        raise CertificateSigningError("Certificate hash is not a SHA-256 hexadecimal value.")
    return f"SEDWTIAR-CERTIFICATE-V2:{certificate_hash.lower()}".encode("ascii")


def sign_certificate_hash(certificate_hash: str) -> dict[str, str]:
    """Sign one canonical certificate hash with the DPAPI-protected key."""
    private_key = _load_or_create_private_key()
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    signature = private_key.sign(_message(certificate_hash))
    public_key = base64.b64encode(public_bytes).decode("ascii")
    return {
        "signature": base64.b64encode(signature).decode("ascii"),
        "signature_algorithm": "Ed25519",
        "signing_key_id": hashlib.sha256(public_bytes).hexdigest()[:24],
        "public_key": public_key,
    }


def local_signing_key_identity() -> tuple[str, str] | None:
    """Return the locally protected signer's identity without creating a key."""
    path = _key_path()
    if not path.exists():
        return None
    private_key = _load_or_create_private_key()
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return hashlib.sha256(public_bytes).hexdigest()[:24], base64.b64encode(public_bytes).decode("ascii")


def verify_certificate_hash(certificate_hash: str, signature: str, public_key: str) -> bool:
    """Verify an Ed25519 signature without loading the private key."""
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True))
        key.verify(base64.b64decode(signature, validate=True), _message(certificate_hash))
        return True
    except (CertificateSigningError, InvalidSignature, ValueError, TypeError):
        return False
