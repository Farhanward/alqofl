from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from alqofl.batch import benchmark_nvd
from alqofl.crypto import ensure_keypair
from alqofl.license import activate, device_fingerprint, issue_license, verify_license


class AlQoflTests(unittest.TestCase):
    def test_issue_and_verify_device_bound_license(self):
        with tempfile.TemporaryDirectory(dir="C:/Projects") as tmp:
            private = Path(tmp) / "private.pem"
            public = Path(tmp) / "public.pem"
            ensure_keypair(private, public)
            device = device_fingerprint(["cpu-a", "disk-b"])
            code = issue_license(
                app_id="app.test",
                customer="user@example.com",
                device_hash=device,
                features=["pro"],
                duration_days=30,
                private_key=private,
            )
            status = verify_license(code, public_key=public, expected_app_id="app.test", device_hash=device)
            self.assertTrue(status.active)
            self.assertIn("pro", status.features)
            self.assertTrue(status.proof)

    def test_wrong_app_and_device_fail(self):
        with tempfile.TemporaryDirectory(dir="C:/Projects") as tmp:
            private = Path(tmp) / "private.pem"
            public = Path(tmp) / "public.pem"
            ensure_keypair(private, public)
            device = device_fingerprint(["box-1"])
            code = issue_license(
                app_id="app.test",
                customer="user@example.com",
                device_hash=device,
                features=["pro"],
                duration_days=30,
                private_key=private,
            )
            self.assertFalse(verify_license(code, public_key=public, expected_app_id="app.other", device_hash=device).active)
            self.assertFalse(verify_license(code, public_key=public, expected_app_id="app.test", device_hash=device_fingerprint(["box-2"])).active)

    def test_invalid_duration_is_rejected(self):
        with tempfile.TemporaryDirectory(dir="C:/Projects") as tmp:
            private = Path(tmp) / "private.pem"
            public = Path(tmp) / "public.pem"
            ensure_keypair(private, public)
            device = device_fingerprint(["box-1"])
            with self.assertRaises(ValueError):
                issue_license(
                    app_id="app.test",
                    customer="user@example.com",
                    device_hash=device,
                    features=["pro"],
                    duration_days=0,
                    private_key=private,
                )

    def test_expired_license_and_nested_activation_path(self):
        with tempfile.TemporaryDirectory(dir="C:/Projects") as tmp:
            root = Path(tmp)
            private = root / "private.pem"
            public = root / "public.pem"
            ensure_keypair(private, public)
            device = device_fingerprint(["box-1"])
            code = issue_license(
                app_id="app.test",
                customer="user@example.com",
                device_hash=device,
                features=["pro"],
                duration_days=1,
                private_key=private,
            )
            expired = verify_license(
                code,
                public_key=public,
                expected_app_id="app.test",
                device_hash=device,
                now=datetime.now(UTC) + timedelta(days=2),
            )
            self.assertFalse(expired.active)
            self.assertEqual(expired.reason, "expired")
            license_path = root / "state" / "licenses" / "active.alq"
            status = activate(
                code,
                public_key=public,
                expected_app_id="app.test",
                device_hash=device,
                license_path=license_path,
                clock_path=root / "state" / "clock.txt",
            )
            self.assertTrue(status.active)
            self.assertTrue(license_path.exists())

    def test_tamper_fails(self):
        with tempfile.TemporaryDirectory(dir="C:/Projects") as tmp:
            private = Path(tmp) / "private.pem"
            public = Path(tmp) / "public.pem"
            ensure_keypair(private, public)
            device = device_fingerprint(["box-1"])
            code = issue_license(
                app_id="app.test",
                customer="user@example.com",
                device_hash=device,
                features=["pro"],
                duration_days=30,
                private_key=private,
            )
            tampered = code[:-2] + ("AA" if not code.endswith("AA") else "BB")
            self.assertFalse(verify_license(tampered, public_key=public, expected_app_id="app.test", device_hash=device).active)

    def test_benchmark_fixture(self):
        with tempfile.TemporaryDirectory(dir="C:/Projects") as tmp:
            path = Path(tmp) / "nvd.jsonl"
            path.write_text('{"id":"CVE-TEST-1","severity":"HIGH"}\n{"id":"CVE-TEST-2","severity":"LOW"}\n', encoding="utf-8")
            summary = benchmark_nvd(path, private_key=Path(tmp) / "private.pem", public_key=Path(tmp) / "public.pem", tamper_every=1)
            self.assertEqual(summary["processed"], 2)
            self.assertEqual(summary["valid_fail"], 0)
            self.assertEqual(summary["tamper_detected"], 2)


if __name__ == "__main__":
    unittest.main()
