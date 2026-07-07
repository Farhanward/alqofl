from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


PRIVATE_KEY = Path("keys") / "alqofl_ed25519_private.pem"
PUBLIC_KEY = Path("keys") / "alqofl_ed25519_public.pem"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode((value + "=" * ((4 - len(value) % 4) % 4)).encode("ascii"))


def ensure_keypair(private_path: str | Path = PRIVATE_KEY, public_path: str | Path = PUBLIC_KEY) -> tuple[Path, Path]:
    private = Path(private_path)
    public = Path(public_path)
    private.parent.mkdir(parents=True, exist_ok=True)
    public.parent.mkdir(parents=True, exist_ok=True)
    if private.exists():
        key = serialization.load_pem_private_key(private.read_bytes(), password=None)
        public_bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if not public.exists() or public.read_bytes() != public_bytes:
            public.write_bytes(public_bytes)
        return private, public
    key = Ed25519PrivateKey.generate()
    private.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private, public


def load_private(path: str | Path = PRIVATE_KEY) -> Ed25519PrivateKey:
    private = Path(path)
    if not private.exists():
        ensure_keypair(private, PUBLIC_KEY)
    return serialization.load_pem_private_key(private.read_bytes(), password=None)


def load_public(path: str | Path = PUBLIC_KEY) -> Ed25519PublicKey:
    public = Path(path)
    if not public.exists():
        ensure_keypair(PRIVATE_KEY, public)
    return serialization.load_pem_public_key(public.read_bytes())


def sign(payload: bytes, private_path: str | Path = PRIVATE_KEY) -> str:
    return b64url(load_private(private_path).sign(payload))


def verify(payload: bytes, signature: str, public_path: str | Path = PUBLIC_KEY) -> bool:
    try:
        load_public(public_path).verify(b64url_decode(signature), payload)
        return True
    except Exception:
        return False


def public_fingerprint(public_path: str | Path = PUBLIC_KEY) -> str:
    data = Path(public_path).read_bytes()
    return hashlib.sha256(data).hexdigest()
