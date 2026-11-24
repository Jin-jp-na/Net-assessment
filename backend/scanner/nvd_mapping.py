import re
from typing import Any, Dict, List, Optional

from .nvd_client import query_nvd_by_keyword


def build_keyword_from_service(product: Optional[str], version: Optional[str]) -> Optional[str]:
    if not product:
        return None
    version_parts = (version or "").split()
    if not version_parts:
        return product

    first = version_parts[0]
    numeric_prefix = re.match(r"[\d.]+", first)
    return f"{product} {numeric_prefix.group() if numeric_prefix else first}"


def extract_cve_summaries(nvd_response: Dict[str, Any]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for item in nvd_response.get("vulnerabilities", []):
        cve = item.get("cve", {})
        descriptions = cve.get("descriptions") or []
        description = descriptions[0].get("value", "") if descriptions else ""
        metrics = cve.get("metrics") or {}
        score = severity = None
        for metric_name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(metric_name)
            if entries:
                metric = entries[0]
                cvss = metric.get("cvssData") or {}
                score = cvss.get("baseScore")
                severity = metric.get("baseSeverity") if metric_name == "cvssMetricV2" else cvss.get("baseSeverity")
                break

        results.append(
            {
                "id": cve.get("id"),
                "severity": severity,
                "score": score,
                "description": description,
            }
        )

    return results


def enrich_service_with_nvd(product: Optional[str], version: Optional[str]) -> Dict[str, Any]:
    keyword = build_keyword_from_service(product, version)
    if not keyword:
        return {"keyword": None, "cves": []}

    try:
        raw = query_nvd_by_keyword(keyword)
        cves = extract_cve_summaries(raw)
        return {"keyword": keyword, "cves": cves}
    except (AttributeError, TypeError, ValueError):
        return {"keyword": keyword, "error": "NVD returned invalid CVE data", "cves": []}