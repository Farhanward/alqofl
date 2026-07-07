from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .crypto import b64url, b64url_decode, sign, verify
from .ledger import append
from .models import LicenseClaims, LicenseEnvelope, LicenseStatus


PREFIX = "ALQ-"
CLOCK_GRACE_SECONDS = 600


def canonical(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _parse_utc(value: str) -> datetime:
    return _as_utc(datetime.fromisoformat(value))


def hash_field(value: str, salt: str = "") -> str:
    normalized = f"{salt}:{value.strip().lower()}"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def device_fingerprint(parts: list[str], salt: str = "alqofl-device-v1") -> str:
    cleaned = [part.strip().lower() for part in parts if part and part.strip()]
    if not cleaned:
        cleaned = ["unknown-device"]
    return hash_field("|".join(sorted(cleaned)), salt=salt)


def encode_envelope(envelope: LicenseEnvelope) -> str:
    return PREFIX + b64url(canonical(envelope.to_dict()))


def decode_envelope(code: str) -> LicenseEnvelope:
    trimmed = code.strip()
    if trimmed.startswith(PREFIX):
        trimmed = trimmed[len(PREFIX):]
    return LicenseEnvelope.from_dict(json.loads(b64url_decode(trimmed).decode("utf-8")))


def issue_license(
    *,
    app_id: str,
    customer: str,
    device_hash: str,
    features: list[str],
    duration_days: int,
    private_key: str | Path = "keys/alqofl_ed25519_private.pem",
    metadata: dict[str, Any] | None = None,
    record_ledger: bool = True,
) -> str:
    if duration_days <= 0:
        raise ValueError("duration_days must be greater than zero")
    now = datetime.now(UTC)
    claims = LicenseClaims(
        license_id=str(uuid.uuid4()),
        app_id=app_id,
        customer_hash=hash_field(customer, salt=app_id),
        device_hash=device_hash,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(days=max(1, duration_days))).isoformat(),
        features=sorted(set(features or ["basic"])),
        max_activations=1,
        metadata=dict(metadata or {}),
    )
    signature = sign(canonical(claims.to_dict()), private_key)
    envelope = LicenseEnvelope(claims=claims, signature=signature)
    code = encode_envelope(envelope)
    if record_ledger:
        append({"kind": "issue", "license_id": claims.license_id, "app_id": app_id, "features": claims.features})
    return code


def usage_proof(envelope: LicenseEnvelope, period: str | None = None) -> str:
    period = period or datetime.now(UTC).strftime("%Y-%m-%d")
    material = {
        "license_id": envelope.claims.license_id,
        "app_id": envelope.claims.app_id,
        "device_hash": envelope.claims.device_hash,
        "period": period,
        "signature": envelope.signature,
    }
    return hashlib.blake2b(canonical(material), digest_size=24).hexdigest()


def _check_clock(now: datetime, clock_path: str | Path | None) -> tuple[bool, str]:
    if clock_path is None:
        return True, "clock check skipped"
    path = Path(clock_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(now.isoformat(), encoding="utf-8")
        return True, "clock initialized"
    try:
        last = datetime.fromisoformat(path.read_text(encoding="utf-8").strip())
    except ValueError:
        return False, "clock state is invalid"
    if now + timedelta(seconds=CLOCK_GRACE_SECONDS) < last:
        return False, "clock rollback detected"
    if now > last:
        path.write_text(now.isoformat(), encoding="utf-8")
    return True, "clock ok"


def verify_license(
    code: str,
    *,
    public_key: str | Path = "keys/alqofl_ed25519_public.pem",
    expected_app_id: str,
    device_hash: str,
    now: datetime | None = None,
    clock_path: str | Path | None = None,
) -> LicenseStatus:
    now = _as_utc(now or datetime.now(UTC))
    try:
        envelope = decode_envelope(code)
    except Exception as exc:
        return LicenseStatus(False, f"decode failed: {exc!r}")
    claims = envelope.claims
    if envelope.alg != "Ed25519":
        return LicenseStatus(False, "unsupported algorithm", claims.license_id, claims.app_id)
    if claims.app_id != expected_app_id:
        return LicenseStatus(False, "wrong app_id", claims.license_id, claims.app_id)
    if claims.device_hash != device_hash:
        return LicenseStatus(False, "device mismatch", claims.license_id, claims.app_id)
    if not verify(canonical(claims.to_dict()), envelope.signature, public_key):
        return LicenseStatus(False, "signature mismatch", claims.license_id, claims.app_id)
    clock_ok, clock_reason = _check_clock(now, clock_path)
    if not clock_ok:
        return LicenseStatus(False, clock_reason, claims.license_id, claims.app_id)
    try:
        issued = _parse_utc(claims.issued_at)
        expires = _parse_utc(claims.expires_at)
    except ValueError:
        return LicenseStatus(False, "invalid license dates", claims.license_id, claims.app_id)
    if issued > now + timedelta(seconds=CLOCK_GRACE_SECONDS):
        return LicenseStatus(False, "license issued in the future", claims.license_id, claims.app_id)
    if expires <= issued:
        return LicenseStatus(False, "invalid expiry", claims.license_id, claims.app_id)
    remaining = expires - now
    if remaining.total_seconds() <= 0:
        return LicenseStatus(False, "expired", claims.license_id, claims.app_id, claims.expires_at, 0, claims.features)
    days = max(0, int(remaining.total_seconds() // 86400))
    return LicenseStatus(
        True,
        clock_reason,
        claims.license_id,
        claims.app_id,
        claims.expires_at,
        days,
        claims.features,
        usage_proof(envelope),
    )


def activate(
    code: str,
    *,
    public_key: str | Path,
    expected_app_id: str,
    device_hash: str,
    license_path: str | Path = "activated_license.alq",
    clock_path: str | Path | None = "clock_guard.txt",
) -> LicenseStatus:
    status = verify_license(
        code,
        public_key=public_key,
        expected_app_id=expected_app_id,
        device_hash=device_hash,
        clock_path=clock_path,
    )
    if status.active:
        path = Path(license_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code.strip(), encoding="utf-8")
        append({"kind": "activate", "license_id": status.license_id, "app_id": status.app_id})
    return status


def status(
    *,
    public_key: str | Path,
    expected_app_id: str,
    device_hash: str,
    license_path: str | Path = "activated_license.alq",
    clock_path: str | Path | None = "clock_guard.txt",
) -> LicenseStatus:
    path = Path(license_path)
    if not path.exists():
        return LicenseStatus(False, "license file missing")
    return verify_license(
        path.read_text(encoding="utf-8"),
        public_key=public_key,
        expected_app_id=expected_app_id,
        device_hash=device_hash,
        clock_path=clock_path,
    )
