#!/bin/sh
# Print the approved base image IMAGE was built FROM: the approved base whose layers are
# the first layers of IMAGE. Labels can't be trusted, because the image's authors set them;
# layers can. When several bases match (one base built on another), the one with the most
# layers wins. Exits 1 if none matches: IMAGE was built from an unapproved base, or was
# squashed or rechunked.
#
# usage: find-base.sh IMAGE APPROVED_BASES
#   IMAGE           registry/repo@sha256:...
#   APPROVED_BASES  file with one base image by digest per line; # starts a comment
#
# Requires skopeo. SKOPEO_OPTS adds options to `skopeo inspect`, e.g. --authfile FILE.
set -eu

if [ $# -ne 2 ]; then
  sed -n '2,12p' "$0" >&2
  exit 2
fi

layers() {
  # Each digest is followed by a space, so a prefix match always ends on a layer boundary.
  # shellcheck disable=SC2086 # SKOPEO_OPTS is a list of options
  skopeo inspect ${SKOPEO_OPTS:-} --format '{{range .Layers}}{{.}} {{end}}' "docker://$1" </dev/null
}

if ! echo "$1" | grep -Eq '^[^@[:space:]]+@sha256:[0-9a-f]{64}$'; then
  echo "$1 is not pinned by digest" >&2
  exit 1
fi
image_layers=$(layers "$1")
best=
best_count=0
while IFS= read -r line || [ -n "$line" ]; do
  base=$(echo "${line%%#*}" | tr -d '[:space:]')
  [ -n "$base" ] || continue
  case $base in
    *@sha256:*) ;;
    *) echo "approved bases must be by digest: $base" >&2; exit 2 ;;
  esac
  base_layers=$(layers "$base")
  case $image_layers in
    "$base_layers"*)
      count=$(echo "$base_layers" | wc -w)
      if [ "$count" -gt "$best_count" ]; then
        best=$base
        best_count=$count
      fi
      ;;
  esac
done < "$2"

if [ -z "$best" ]; then
  echo "no approved base matches the first layers of $1" >&2
  exit 1
fi
echo "$best"
