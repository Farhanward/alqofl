from __future__ import annotations

from typing import Any


def benchmark_markdown(summary: dict[str, Any]) -> str:
    latency = summary.get("latency_ms", {})
    memory = summary.get("memory_mb", {})
    return "\n".join(
        [
            "# تقرير القفل",
            "",
            f"- الملف: `{summary.get('input')}`",
            f"- الرخص المعالجة: `{summary.get('processed')}`",
            f"- الرخص الصحيحة: `{summary.get('valid_ok')}`",
            f"- فشل التحقق الصحيح: `{summary.get('valid_fail')}`",
            f"- اختبارات التلاعب: `{summary.get('tamper_checks')}`",
            f"- التلاعب المكتشف: `{summary.get('tamper_detected')}`",
            f"- الأخطاء: `{summary.get('errors')}`",
            f"- الانهيار: `{'PASS' if summary.get('collapse_check', {}).get('passed') else 'FAIL'}`",
            "",
            "## الجودة",
            "",
            f"- valid accuracy: `{summary.get('accuracy', 0):.4f}`",
            f"- tamper detection: `{summary.get('tamper_detection_rate', 0):.4f}`",
            "",
            "## الأداء",
            "",
            f"- mean: `{latency.get('mean', 0):.4f}ms`",
            f"- p50: `{latency.get('p50', 0):.4f}ms`",
            f"- p95: `{latency.get('p95', 0):.4f}ms`",
            f"- p99: `{latency.get('p99', 0):.4f}ms`",
            f"- max: `{latency.get('max', 0):.4f}ms`",
            f"- peak memory: `{memory.get('peak', 0):.4f}MB`",
            f"- elapsed: `{summary.get('elapsed_seconds', 0):.2f}s`",
            "",
        ]
    )
