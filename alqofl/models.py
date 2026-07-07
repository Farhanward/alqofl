from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class LicenseClaims:
    license_id: str
    app_id: str
    customer_hash: str
    device_hash: str
    issued_at: str
    expires_at: str
    features: list[str] = field(default_factory=list)
    max_activations: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "license_id": self.license_id,
            "app_id": self.app_id,
            "customer_hash": self.customer_hash,
            "device_hash": self.device_hash,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "features": self.features,
            "max_activations": self.max_activations,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LicenseClaims":
        return cls(
            license_id=str(data["license_id"]),
            app_id=str(data["app_id"]),
            customer_hash=str(data["customer_hash"]),
            device_hash=str(data["device_hash"]),
            issued_at=str(data["issued_at"]),
            expires_at=str(data["expires_at"]),
            features=[str(item) for item in data.get("features") or []],
            max_activations=int(data.get("max_activations") or 1),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass
class LicenseEnvelope:
    claims: LicenseClaims
    signature: str
    alg: str = "Ed25519"
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "alg": self.alg,
            "claims": self.claims.to_dict(),
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LicenseEnvelope":
        return cls(
            version=int(data.get("version") or 1),
            alg=str(data.get("alg") or "Ed25519"),
            claims=LicenseClaims.from_dict(dict(data["claims"])),
            signature=str(data["signature"]),
        )


@dataclass
class LicenseStatus:
    active: bool
    reason: str
    license_id: str = ""
    app_id: str = ""
    expires_at: str = ""
    days_remaining: int = 0
    features: list[str] = field(default_factory=list)
    proof: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "active": self.active,
            "reason": self.reason,
            "license_id": self.license_id,
            "app_id": self.app_id,
            "expires_at": self.expires_at,
            "days_remaining": self.days_remaining,
            "features": self.features,
            "proof": self.proof,
        }
