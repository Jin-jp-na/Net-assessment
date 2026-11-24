from typing import Dict, Any, List

SENSITIVE_SERVICES = {"ssh", "rdp", "mysql", "mssql", "postgresql", "smb"}
WEB_SERVICES = {"http", "https"}


def base_risk(service: Dict[str, Any]) -> int:
    name = (service.get("service") or "").lower()
    port = service.get("port")
    if name in SENSITIVE_SERVICES or port in {22, 3389, 3306, 5432, 1433}:
        return 25
    if name in WEB_SERVICES or port in {80, 443, 8080, 8443}:
        return 20
    return 10


def exposure_risk(exposure: str) -> int:
    if exposure == "external":
        return 25
    if exposure == "internal":
        return 10
    return 15  # unknown / mixed


def exploitability_risk(nvd_block: Dict[str, Any]) -> int:
    cves = nvd_block.get("cves", []) if nvd_block else []
    if not cves:
        return 0

    points = {"CRITICAL": 25, "HIGH": 20, "MEDIUM": 10}
    return max(points.get((cve.get("severity") or "").upper(), 5) for cve in cves)


def privilege_risk(service: Dict[str, Any]) -> int:
    name = (service.get("service") or "").lower()
    # simple assumption: these typically grant high privileges if taken over
    if name in {"ssh", "rdp", "smb", "mysql", "mssql", "postgresql"}:
        return 20
    if name in WEB_SERVICES:
        return 10
    return 5  # unknown


def heuristic_credential_risk(service: Dict[str, Any]) -> int:
    name = (service.get("service") or "").lower()
    if name in {"ftp", "ssh", "telnet", "rdp", "smb", "vnc"}:
        return 10
    return 0


def confirmed_credential_risk(service: Dict[str, Any]) -> int:
    weak = (service.get("weak_creds") or {}).get("found", False)
    return 25 if weak else 0


def attack_path_risk(service: Dict[str, Any], exposure: str) -> int:
    name = (service.get("service") or "").lower()
    # external sensitive services are entry points
    if exposure == "external" and (name in SENSITIVE_SERVICES or name in WEB_SERVICES):
        return 10
    # later you can add logic for lateral movement, etc.
    return 0


def clamp(score: int) -> int:
    return max(0, min(100, score))


def pcvp_score_for_service(service: Dict[str, Any], exposure: str) -> Dict[str, Any]:
    nvd_block = service.get("nvd", {}) or {}

    base = base_risk(service)
    exposure_points = exposure_risk(exposure)
    cve_points = exploitability_risk(nvd_block)
    privilege = privilege_risk(service)
    common_credentials = heuristic_credential_risk(service)
    confirmed_credentials = confirmed_credential_risk(service)
    entry_point = attack_path_risk(service, exposure)
    total = clamp(base + exposure_points + cve_points + privilege + common_credentials
                  + confirmed_credentials + entry_point)

    # Map numeric score to a label
    if total >= 80:
        level = "critical"
    elif total >= 60:
        level = "high"
    elif total >= 40:
        level = "medium"
    elif total >= 20:
        level = "low"
    else:
        level = "informational"

    reasons: List[str] = [
        f"Base service/port risk: {base}",
        f"Exposure ({exposure}): {exposure_points}",
    ]
    if cve_points:
        reasons.append(f"Exploitability from NVD CVEs: {cve_points}")
    if privilege:
        reasons.append(f"Privilege impact: {privilege}")
    if common_credentials:
        reasons.append("Service type commonly affected by weak/default credentials.")
    if confirmed_credentials:
        reasons.append("Confirmed weak/default credentials detected.")
    if entry_point:
        reasons.append("Service is a likely entry point in an attack path.")

    return {
        "pcvp_score": total,
        "pcvp_level": level,
        "pcvp_reasons": reasons,
    }