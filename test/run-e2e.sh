#!/usr/bin/env bash
# End-to-end test: build the images in test/images, push them to a throwaway local
# registry, run scripts/check-image.sh against each, and compare the findings with what
# each image should produce.
#
# Requires podman, curl, jq and python3. Uses syft and conftest from PATH when installed,
# otherwise runs the pinned container images below.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work="$root/.work/e2e"
registry=localhost:5002
SYFT_IMAGE=docker.io/anchore/syft:v1.56.0
CONFTEST_IMAGE=docker.io/openpolicyagent/conftest:v0.71.1
REGISTRY_IMAGE=docker.io/library/registry:2

export SYFT_FILE_METADATA_SELECTION=all
export SYFT_FILE_METADATA_DIGESTS=sha256
export SYFT_CHECK_FOR_APP_UPDATE=false
export SYFT_REGISTRY_INSECURE_USE_HTTP=true # the local registry has no TLS

rm -rf "$work"
mkdir -p "$work/bin"
if ! command -v syft >/dev/null; then
  cat > "$work/bin/syft" <<EOF
#!/bin/sh
exec podman run --rm --network host -v "$root:$root:Z" -e SYFT_FILE_METADATA_SELECTION -e SYFT_FILE_METADATA_DIGESTS -e SYFT_CHECK_FOR_APP_UPDATE -e SYFT_REGISTRY_INSECURE_USE_HTTP $SYFT_IMAGE "\$@"
EOF
fi
if ! command -v conftest >/dev/null; then
  cat > "$work/bin/conftest" <<EOF
#!/bin/sh
exec podman run --rm -v "$root:$root:Z" -w "$root" $CONFTEST_IMAGE "\$@"
EOF
fi
chmod +x "$work"/bin/* 2>/dev/null || true
export PATH="$work/bin:$PATH"

# The registry stores the base's layers once for all images, and is discarded on exit.
podman run -d --rm --name integrity-e2e-registry -p 5002:5000 "$REGISTRY_IMAGE" >/dev/null
trap 'podman stop integrity-e2e-registry >/dev/null' EXIT
until curl -fs "http://$registry/v2/" >/dev/null; do sleep 0.2; done

# build NAME DIR [PODMAN_BUILD_ARGS...]: builds and pushes, then records the pushed
# reference (by digest) in $work/NAME.ref.
build() {
  local name=$1 dir=$2
  shift 2
  echo "building $name"
  podman build -q "$@" -t "localhost/integrity-test/$name:latest" "$root/test/images/$dir" >/dev/null
  # Not -q: podman does not write --digestfile in quiet mode.
  podman push --tls-verify=false --digestfile "$work/$name.digest" \
    "localhost/integrity-test/$name:latest" "$registry/integrity-test/$name:latest" >/dev/null 2>&1
  echo "$registry/integrity-test/$name@$(cat "$work/$name.digest")" > "$work/$name.ref"
}

build base base
build good good
build tampered tampered
build tampered-squashed tampered --squash-all

# Every case compares against the same base, so inventory it once.
syft scan "registry:$(cat "$work/base.ref")" -q -o "syft-json=$work/base.syft.json"

failed=0

# run_case NAME IMAGE DATA_DIRS EXPECTED_FAILURES [EXPECTED_WARNING_SUBSTRING...]
# EXPECTED_FAILURES is one "kind path" per line, matching the start of each failure message.
run_case() {
  local name=$1 image=$2 data=$3 expected=$4
  shift 4
  local out="$work/$name"
  WORK_DIR="$out" DATA_DIRS="$data" BASE_SYFT_JSON="$work/base.syft.json" \
    "$root/scripts/check-image.sh" \
    "registry:$(cat "$work/base.ref")" "registry:$(cat "$work/$image.ref")" \
    > "$out.log" 2>&1 || true

  local problems=()
  if [[ ! -s "$out/results.json" ]]; then
    problems+=("no conftest output; see $out.log")
  else
    local actual want
    actual=$(jq -r '.[].failures[]?.msg | split(":")[0]' "$out/results.json" | sort)
    want=$(sed '/^$/d' <<<"$expected" | sort)
    if [[ "$actual" != "$want" ]]; then
      problems+=("failures differ (- expected, + actual):")
      problems+=("$(diff <(echo "$want") <(echo "$actual") | grep '^[<>]' | sed 's/^</-/; s/^>/+/')")
    fi
    local warnings count
    warnings=$(jq -r '.[].warnings[]?.msg' "$out/results.json")
    count=$(sed '/^$/d' <<<"$warnings" | wc -l | tr -d ' ')
    if [[ "$count" -ne $# ]]; then
      problems+=("expected $# warning(s), got $count:" "$warnings")
    fi
    local w
    for w in "$@"; do
      grep -qF -- "$w" <<<"$warnings" || problems+=("missing warning: $w")
    done
  fi

  if [[ ${#problems[@]} -eq 0 ]]; then
    echo "PASS  $name"
  else
    echo "FAIL  $name"
    printf '      %s\n' "${problems[@]}"
    failed=1
  fi
}

tampered_findings='modified /opt/agent/bin/agent
deleted /usr/bin/auditctl
added /etc/ssh/sshd_config.d/01-debug.conf
modified /etc/ssh/sshd_config.d/00-hardening.conf
added /etc/rsyslog.d/00-app.conf
added /etc/sysctl.d/99-hardening.conf
added /etc/systemd/system/agent.service.d/override.conf
deleted /etc/systemd/system/multi-user.target.wants/agent.service
added /etc/ld.so.preload
added /usr/local/bin/sshd'

run_case base-vs-itself base "$root/test/data" ''
run_case good good "$root/test/data" ''
run_case tampered tampered "$root/test/data" "$tampered_findings
touched /usr/bin/sshd"
# Squashing loses layer attribution, so `touch` goes unnoticed; content changes do not.
run_case tampered-squashed tampered-squashed "$root/test/data" "$tampered_findings" \
  'base layers are not an unchanged prefix'
run_case tampered-with-exceptions tampered "$root/test/data $root/test/exceptions" \
  "$(grep -v ld.so.preload <<<"$tampered_findings")
touched /usr/bin/sshd" \
  'allowed by exception TEST-1 until 2099-01-01: added /etc/ld.so.preload' \
  'exception TEST-2 for /usr/local/bin/* expired on 2020-01-01'

exit $failed
