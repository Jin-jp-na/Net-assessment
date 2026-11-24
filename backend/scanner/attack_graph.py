from typing import Dict, Any, List, Tuple

def _extract_cves(svc: Dict[str, Any]) -> List[Dict[str, Any]]:
    nvd = svc.get("nvd") or {}
    for key in ("cves", "items", "results", "vulns"):
        if isinstance(nvd.get(key), list):
            return nvd[key]
    if isinstance(svc.get("mapped_cves"), list):
        return svc["mapped_cves"]
    return []

def build_attack_graph(parsed_scan: Dict[str, Any]) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    node_ids = set()
    edge_keys = set()

    def add_node(node: Dict[str, Any]) -> None:
        node_id = node["id"]
        if node_id not in node_ids:
            node_ids.add(node_id)
            nodes.append(node)

    def add_edge(source: str, target: str, relation: str) -> None:
        key = (source, target, relation)
        if key not in edge_keys:
            edge_keys.add(key)
            edges.append({"from": source, "to": target, "relation": relation})

    def service_id(ip: str, svc: Dict[str, Any]) -> str:
        return f"svc:{ip}:{svc.get('port')}/{svc.get('protocol', 'tcp')}"

    hosts = parsed_scan.get("hosts", [])
    for host in hosts:
        ip = host.get("ip")
        if not ip:
            continue

        host_node_id = f"host:{ip}"
        add_node({"id": host_node_id, "type": "host", "ip": ip})

        for svc in host.get("services", []):
            sid = service_id(ip, svc)

            add_node({
                "id": sid,
                "type": "service",
                "ip": ip,
                "port": svc.get("port"),
                "protocol": svc.get("protocol"),
                "service": svc.get("service"),
                "pcvp_score": svc.get("pcvp_score"),
                "pcvp_level": svc.get("pcvp_level"),
            })

            add_edge(host_node_id, sid, "runs")

            # ✅ Use robust CVE extraction
            for c in _extract_cves(svc):
                cve_value = (c.get("cve_id") or c.get("id") or c.get("cve") or "").strip()
                if not cve_value:
                    continue  # prevents cve:unknown duplicates

                cid = f"cve:{cve_value}"
                add_node({
                    "id": cid,
                    "type": "cve",
                    "cve_id": cve_value,
                    "severity": c.get("severity"),
                    "cvss": c.get("cvss") or c.get("score"),
                })
                add_edge(sid, cid, "has_vulnerability")

    high_services: List[Tuple[Dict[str, Any], Dict[str, Any]]] = [
        (host, svc) for host in hosts
        for svc in host.get("services", [])
        if (svc.get("pcvp_level") in {"high", "critical"})
    ]
    for idx, (host_a, svc_a) in enumerate(high_services):
        ip_a = host_a.get("ip")
        if not ip_a:
            continue
        sid_a = service_id(ip_a, svc_a)

        for host_b, svc_b in high_services[idx + 1:]:
            ip_b = host_b.get("ip")
            if not ip_b:
                continue
            sid_b = service_id(ip_b, svc_b)

            add_edge(sid_a, sid_b, "possible_chain")

    return {"nodes": nodes, "edges": edges}