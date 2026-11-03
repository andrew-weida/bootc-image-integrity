#!/usr/bin/env bash
# Check a derived bootc image against the base it was built FROM.
#
# usage: check-image.sh BASE IMAGE [IMAGE_REF]
#   BASE, IMAGE  syft sources, e.g. registry:quay.io/org/base@sha256:... or oci-archive:/tmp/app.tar
#   IMAGE_REF    reference exceptions are matched against (repository part).
#                Defaults to IMAGE with any syft scheme removed.
#
# Requires syft, conftest and python3 on PATH.
# Environment:
#   DATA_DIRS       space-separated conftest data directories (default: <repo>/data)
#   WORK_DIR        keep intermediate files here (default: a temporary directory, removed on exit)
#   BASE_SYFT_JSON  existing syft-json inventory of BASE; skips scanning BASE again
#   KEEP_SYFT       set to "true" to keep the syft inventories after flattening
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  sed -n '2,15p' "$0" >&2
  exit 2
fi

root=$(cd "$(dirname "$0")/.." && pwd)
base=$1
image=$2
image_ref=${3:-$image}
case $image_ref in
  registry:* | docker:* | podman:* | containerd:*) image_ref=${image_ref#*:} ;;
  oci-archive:* | oci-dir:* | docker-archive:* | dir:*)
    echo "warning: IMAGE is a local archive; pass IMAGE_REF so exceptions can match" >&2 ;;
esac

work=${WORK_DIR:-}
if [[ -z $work ]]; then
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
fi
mkdir -p "$work"

export SYFT_FILE_METADATA_SELECTION=all
export SYFT_FILE_METADATA_DIGESTS=sha256
export SYFT_CHECK_FOR_APP_UPDATE=false

base_json=${BASE_SYFT_JSON:-}
if [[ -z $base_json ]]; then
  base_json="$work/base.syft.json"
  syft scan "$base" -q -o "syft-json=$base_json"
fi
syft scan "$image" -q -o "syft-json=$work/image.syft.json"

python3 "$root/scripts/flatten-syft.py" \
  --base "$base_json" --image "$work/image.syft.json" \
  --base-ref "$base" --image-ref "$image_ref" > "$work/input.json"

# The inventories are several times larger than the flattened input.
if [[ ${KEEP_SYFT:-} != true ]]; then
  rm -f "$work/image.syft.json"
  [[ -n ${BASE_SYFT_JSON:-} ]] || rm -f "$base_json"
fi

data_args=()
for d in ${DATA_DIRS:-$root/data}; do
  data_args+=(--data "$d")
done

# conftest exits 1 on policy failures; report.py decides the final status.
conftest test "$work/input.json" --policy "$root/policy" "${data_args[@]}" \
  --output json > "$work/results.json" || true

python3 "$root/scripts/report.py" "$work/results.json"
