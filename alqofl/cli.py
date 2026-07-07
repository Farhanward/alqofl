from __future__ import annotations

import argparse
import json
from pathlib import Path

from .batch import benchmark_nvd
from .crypto import ensure_keypair, public_fingerprint
from .ledger import verify_ledger
from .license import activate, decode_envelope, device_fingerprint, issue_license, status, usage_proof, verify_license
from .reports import benchmark_markdown


def _write_json(path: str | Path, data: dict) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_text(path: str | Path, text: str) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="alqofl", description="القفل: ترخيص Ed25519 بلا خادم.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    keygen = sub.add_parser("keygen")
    keygen.add_argument("--private", default="keys/alqofl_ed25519_private.pem")
    keygen.add_argument("--public", default="keys/alqofl_ed25519_public.pem")

    fp = sub.add_parser("fingerprint")
    fp.add_argument("parts", nargs="+")
    fp.add_argument("--salt", default="alqofl-device-v1")

    issue = sub.add_parser("issue")
    issue.add_argument("--app-id", required=True)
    issue.add_argument("--customer", required=True)
    issue.add_argument("--device-hash", required=True)
    issue.add_argument("--feature", action="append", default=[])
    issue.add_argument("--days", type=int, default=30)
    issue.add_argument("--private", default="keys/alqofl_ed25519_private.pem")

    verify_cmd = sub.add_parser("verify")
    verify_cmd.add_argument("--code", required=True)
    verify_cmd.add_argument("--app-id", required=True)
    verify_cmd.add_argument("--device-hash", required=True)
    verify_cmd.add_argument("--public", default="keys/alqofl_ed25519_public.pem")

    activate_cmd = sub.add_parser("activate")
    activate_cmd.add_argument("--code", required=True)
    activate_cmd.add_argument("--app-id", required=True)
    activate_cmd.add_argument("--device-hash", required=True)
    activate_cmd.add_argument("--public", default="keys/alqofl_ed25519_public.pem")
    activate_cmd.add_argument("--license-path", default="activated_license.alq")
    activate_cmd.add_argument("--clock-path", default="clock_guard.txt")

    status_cmd = sub.add_parser("status")
    status_cmd.add_argument("--app-id", required=True)
    status_cmd.add_argument("--device-hash", required=True)
    status_cmd.add_argument("--public", default="keys/alqofl_ed25519_public.pem")
    status_cmd.add_argument("--license-path", default="activated_license.alq")
    status_cmd.add_argument("--clock-path", default="clock_guard.txt")

    proof = sub.add_parser("proof")
    proof.add_argument("--code", required=True)
    proof.add_argument("--period", default="")

    bench = sub.add_parser("benchmark")
    bench.add_argument("--input", default="C:/Projects/kashif/data/external/nvd_cves_12000.jsonl")
    bench.add_argument("--json-out", default="reports/alqofl_nvd_benchmark.json")
    bench.add_argument("--report", default="reports/alqofl_nvd_benchmark.md")
    bench.add_argument("--limit", type=int, default=0)
    bench.add_argument("--tamper-every", type=int, default=17)

    sub.add_parser("verify-ledger")

    serve = sub.add_parser("serve")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)

    sub.add_parser("version")
    args = parser.parse_args(argv)

    if args.cmd == "serve":
        from .service import run_server

        run_server(host=args.host, port=args.port)
        return 0
    if args.cmd == "version":
        from .version import __version__

        print(json.dumps({"service": "alqofl", "version": __version__}, ensure_ascii=False))
        return 0

    if args.cmd == "keygen":
        private, public = ensure_keypair(args.private, args.public)
        result = {"private": str(private.resolve()), "public": str(public.resolve()), "public_fingerprint": public_fingerprint(public)}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "fingerprint":
        print(device_fingerprint(args.parts, salt=args.salt))
        return 0
    if args.cmd == "issue":
        if args.days <= 0:
            parser.error("--days must be greater than zero")
        code = issue_license(
            app_id=args.app_id,
            customer=args.customer,
            device_hash=args.device_hash,
            features=args.feature,
            duration_days=args.days,
            private_key=args.private,
        )
        print(code)
        return 0
    if args.cmd == "verify":
        result = verify_license(args.code, public_key=args.public, expected_app_id=args.app_id, device_hash=args.device_hash)
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        return 0 if result.active else 2
    if args.cmd == "activate":
        result = activate(
            args.code,
            public_key=args.public,
            expected_app_id=args.app_id,
            device_hash=args.device_hash,
            license_path=args.license_path,
            clock_path=args.clock_path,
        )
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        return 0 if result.active else 2
    if args.cmd == "status":
        result = status(
            public_key=args.public,
            expected_app_id=args.app_id,
            device_hash=args.device_hash,
            license_path=args.license_path,
            clock_path=args.clock_path,
        )
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        return 0 if result.active else 2
    if args.cmd == "proof":
        envelope = decode_envelope(args.code)
        print(usage_proof(envelope, period=args.period or None))
        return 0
    if args.cmd == "benchmark":
        summary = benchmark_nvd(args.input, limit=args.limit, tamper_every=args.tamper_every)
        _write_json(args.json_out, summary)
        _write_text(args.report, benchmark_markdown(summary))
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0 if summary["collapse_check"]["passed"] else 2
    if args.cmd == "verify-ledger":
        print(json.dumps(verify_ledger(), ensure_ascii=False, indent=2))
        return 0
    raise ValueError(args.cmd)


if __name__ == "__main__":
    raise SystemExit(main())
