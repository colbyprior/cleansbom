"""Summarise Trivy JSON scans: direct vs transitive, prod vs dev, per ecosystem.

Usage: python3 -I scripts/report.py sbom/scans/*.json [--detail]
"""
import json
import sys
from collections import Counter
from pathlib import Path

COLS = ["direct/prod", "transitive/prod", "direct/dev", "transitive/dev", "unknown"]


def bucket(pkg):
    rel = pkg.get("Relationship")
    if rel not in ("direct", "indirect"):
        return "unknown"  # requirements.txt, container images, SBOM re-scans
    return f"{'direct' if rel == 'direct' else 'transitive'}/{'dev' if pkg.get('Dev') else 'prod'}"


def key(pkg_id, name, version):
    return pkg_id or f"{name}@{version}"


def summarise(path, detail):
    report = json.loads(Path(path).read_text())
    for res in report.get("Results", []):
        pkgs = {key(p.get("ID"), p["Name"], p["Version"]): p for p in res.get("Packages", [])}
        vulns = res.get("Vulnerabilities") or []
        counts, sev, unfixable = Counter(), Counter(), set()
        for v in vulns:
            counts[bucket(pkgs.get(key(v.get("PkgID"), v["PkgName"], v["InstalledVersion"]), {}))] += 1
            sev[v["Severity"]] += 1
            if not v.get("FixedVersion"):
                unfixable.add(f"{v['PkgName']}@{v['InstalledVersion']}")
        label = f"{Path(path).stem} :: {res['Target']} [{res['Type']}]"
        print(f"{label}\n  pkgs={len(pkgs):<4} vulns={len(vulns):<4} "
              f"CRIT={sev['CRITICAL']} HIGH={sev['HIGH']} pkgs-with-no-fix={len(unfixable)}")
        print("  " + "  ".join(f"{c}={counts[c]}" for c in COLS if counts[c]))
        if detail:
            for v in sorted(vulns, key=lambda v: (v["PkgName"], v["VulnerabilityID"])):
                b = bucket(pkgs.get(key(v.get("PkgID"), v["PkgName"], v["InstalledVersion"]), {}))
                print(f"    {b:<16} {v['PkgName']:<18} {v['InstalledVersion']:<12} "
                      f"{v['Severity']:<9} {v['VulnerabilityID']:<20} fix={v.get('FixedVersion') or '-'}")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--detail"]
    for f in args:
        summarise(f, "--detail" in sys.argv)
