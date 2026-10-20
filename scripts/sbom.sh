#!/usr/bin/env bash
# Generate CycloneDX SBOMs with Trivy for every part of the demo, then a triage report.
#
#   sbom/*.cdx.json      -> the SBOMs (inventory you'd archive / ship to Dependency-Track)
#   sbom/scans/*.json    -> Trivy vuln scans with Relationship + Dev metadata (for triage)
#
# Usage: scripts/sbom.sh [--no-image]
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=sbom; mkdir -p "$OUT/scans"
IMAGE=cleansbom-demo:latest
T="trivy --quiet"

sbom() {  # name, target-type, target, extra flags...
  local name=$1 kind=$2 target=$3; shift 3
  echo "• $name  ($kind $target $*)"
  $T "$kind" --format cyclonedx "$@" -o "$OUT/$name.cdx.json" "$target"
  $T "$kind" --scanners vuln --format json --list-all-pkgs "$@" -o "$OUT/scans/$name.json" "$target"
}

echo "== Source SBOMs (lockfile-based: knows direct vs transitive, dev vs prod)"
sbom frontend          fs frontend/package-lock.json                     # prod deps only (Trivy default)
sbom frontend.dev      fs frontend/package-lock.json --include-dev-deps  # + devDependencies
sbom backend           fs backend/uv.lock
sbom backend.dev       fs backend/uv.lock --include-dev-deps
sbom backend-legacy-requirements fs backend/legacy/requirements.txt
sbom frontend-pinned   fs examples/frontend-pinned/package-lock.json
sbom frontend-pinned.triaged fs examples/frontend-pinned/package-lock.json --ignorefile .trivyignore.yaml

if [[ "${1:-}" != "--no-image" ]]; then
  echo "== Container SBOM (Trivy discovers OS + npm + Python from the image itself)"
  docker image inspect "$IMAGE" >/dev/null 2>&1 || docker build -t "$IMAGE" .
  sbom image image "$IMAGE"
  # Re-scan the SBOM file itself: this is what a consumer of the SBOM would see.
  $T sbom --scanners vuln --format json --list-all-pkgs -o "$OUT/scans/image.from-sbom.json" "$OUT/image.cdx.json"
fi

echo
python3 -I scripts/report.py "$OUT"/scans/*.json
