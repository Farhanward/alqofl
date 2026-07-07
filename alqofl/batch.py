from __future__ import annotations

import json
import statistics
import time
import tracemalloc
from pathlib import Path
from typing import Any

from .crypto import ensure_keypair
from .license import device_fingerprint, issue_license, verify_license


def _iter_jsonl(path: str | Path):
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def _severity(record: dict[str, Any]) -> str:
    metrics = record.get("metrics") or {}
    if isinstance(metrics, dict):
        cvss = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2") or []
        if cvss:
            item = cvss[0]
            if isinstance(item, dict):
                data = item.get("cvssData") or {}
                if data.get("baseSeverity"):
                    return str(data["baseSeverity"])
                if item.get("baseSeverity"):
                    return str(item["baseSeverity"])
    vuln = record.get("vuln") if isinstance(record.get("vuln"), dict) else record
    return str(vuln.get("severity") or record.get("severity") or "UNKNOWN")


def _cve_id(record: dict[str, Any], index: int) -> str:
    if "id" in record:
        return str(record["id"])
    vuln = record.get("vuln") if isinstance(record.get("vuln"), dict) else record
    return str(vuln.get("id") or f"CVE-SYNTH-{index}")


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((pct / 100) * (len(ordered) - 1)))))
    return ordered[idx]


def benchmark_nvd(
    input_path: str | Path,
    *,
    limit: int = 0,
    private_key: str | Path = "keys/alqofl_ed25519_private.pem",
    public_key: str | Path = "keys/alqofl_ed25519_public.pem",
    app_id: str = "app.alqofl.demo",
    tamper_every: int = 17,
) -> dict[str, Any]:
    ensure_keypair(private_key, public_key)
    records = list(_iter_jsonl(input_path))
    if limit > 0:
        records = records[:limit]
    sign_verify_latencies: list[float] = []
    tamper_checks = tamper_detected = valid_ok = valid_fail = errors = 0
    started = time.perf_counter()
    tracemalloc.start()
    for index, record in enumerate(records, start=1):
        item_started = time.perf_counter()
        try:
            cve = _cve_id(record, index)
            severity = _severity(record).upper()
            device_hash = device_fingerprint([cve, severity, f"device-{index % 97}"])
            features = ["basic", severity.lower()]
            code = issue_license(
                app_id=app_id,
                customer=f"{cve}@example.invalid",
                device_hash=device_hash,
                features=features,
                duration_days=30 + (index % 365),
                private_key=private_key,
                metadata={"source": "nvd", "cve": cve, "severity": severity},
                record_ledger=False,
            )
            status = verify_license(code, public_key=public_key, expected_app_id=app_id, device_hash=device_hash)
            if status.active:
                valid_ok += 1
            else:
                valid_fail += 1
            if tamper_every > 0 and index % tamper_every == 0:
                tamper_checks += 1
                tampered = code[:-2] + ("AA" if not code.endswith("AA") else "BB")
                tampered_status = verify_license(tampered, public_key=public_key, expected_app_id=app_id, device_hash=device_hash)
                if not tampered_status.active:
                    tamper_detected += 1
        except Exception:
            errors += 1
        sign_verify_latencies.append((time.perf_counter() - item_started) * 1000)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    processed = len(records)
    return {
        "input": str(Path(input_path).resolve()),
        "processed": processed,
        "valid_ok": valid_ok,
        "valid_fail": valid_fail,
        "tamper_checks": tamper_checks,
        "tamper_detected": tamper_detected,
        "errors": errors,
        "accuracy": valid_ok / processed if processed else 0.0,
        "tamper_detection_rate": tamper_detected / tamper_checks if tamper_checks else 1.0,
        "latency_ms": {
            "mean": statistics.fmean(sign_verify_latencies) if sign_verify_latencies else 0.0,
            "p50": _percentile(sign_verify_latencies, 50),
            "p95": _percentile(sign_verify_latencies, 95),
            "p99": _percentile(sign_verify_latencies, 99),
            "max": max(sign_verify_latencies) if sign_verify_latencies else 0.0,
        },
        "memory_mb": {"current": current / 1_000_000, "peak": peak / 1_000_000},
        "elapsed_seconds": time.perf_counter() - started,
        "collapse_check": {
            "passed": errors == 0 and valid_fail == 0 and tamper_detected == tamper_checks,
            "criteria": "errors == 0 and valid_fail == 0 and tamper_detected == tamper_checks",
        },
    }
