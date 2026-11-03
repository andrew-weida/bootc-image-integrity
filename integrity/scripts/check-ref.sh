#!/bin/sh
# Exit non-zero unless IMAGE is pinned by digest and names a single image manifest.
#
# A tag can move between checking and signing, so the image signed could differ from the
# image checked. An index of platforms would be checked for one platform only, and hosts
# verify the signature of their platform's own manifest, not the index's.
#
# usage: check-ref.sh IMAGE
# Requires skopeo. SKOPEO_OPTS adds options to `skopeo inspect`, e.g. --authfile FILE.
set -eu

if [ $# -ne 1 ]; then
  sed -n '2,9p' "$0" >&2
  exit 2
fi

if ! echo "$1" | grep -Eq '^[^@[:space:]]+@sha256:[0-9a-f]{64}$'; then
  echo "$1 is not pinned by digest (registry/repo@sha256:<64 hex digits>)" >&2
  exit 1
fi

# shellcheck disable=SC2086 # SKOPEO_OPTS is a list of options
manifest=$(skopeo inspect ${SKOPEO_OPTS:-} --raw "docker://$1" </dev/null)
case $manifest in
  *'"manifests"'*)
    echo "$1 is an index of several platforms; check and sign each platform's image digest instead" >&2
    exit 1
    ;;
  *'"layers"'*) ;;
  *)
    echo "$1 is not an OCI or Docker v2 image manifest" >&2
    exit 1
    ;;
esac
