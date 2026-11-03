#!/usr/bin/env bash
# Exercise the verify-and-sign flow with podman instead of a cluster: run the steps of
# signing/tekton/bootc-find-base-task.yaml, bootc-sign-image-task.yaml and bootc-revoke-signature-task.yaml
# in their images against a throwaway local registry, then check the result with
# signing/signature-policy/ the way a host would. The images come from
# integrity/test/run-e2e.sh, which must have built them.
#
# usage: signing/test/run-verify-locally.sh
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd) # the Tasks see the whole repository as their checkout
root="$repo/signing"
work="$root/.work/verify"
registry=localhost:5003
YQ_IMAGE=docker.io/mikefarah/yq:4
REGISTRY_IMAGE=docker.io/library/registry:2
SKOPEO_IMAGE=quay.io/skopeo/stable:v1.22.3
COSIGN_IMAGE=gcr.io/projectsigstore/cosign:v3.1.4-dev

rm -rf "$work"
mkdir -p "$work/work" "$work/host/registries.d" "$work/logs" "$work/key"
log=/dev/null # each check sets its own

podman run -d --rm --name integrity-verify-registry -p 5003:5000 \
  -e REGISTRY_STORAGE_DELETE_ENABLED=true "$REGISTRY_IMAGE" >/dev/null
trap 'podman stop integrity-verify-registry >/dev/null' EXIT
until curl -fs "http://$registry/v2/" >/dev/null; do sleep 0.2; done

# The local registry speaks plain HTTP.
printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$registry" > "$work/registries.conf"

push() {
  podman push --tls-verify=false --digestfile "$work/$1.digest" \
    "localhost/integrity-test/$1:latest" "$registry/apps/$1:latest" >/dev/null 2>&1
  echo "$registry/apps/$1@$(cat "$work/$1.digest")"
}
base=$(push base)
good=$(push good)
tampered=$(push tampered)

# The same unsigned image as tampered, but in the namespace the host policy accepts unsigned.
podman push --tls-verify=false --digestfile "$work/container.digest" \
  localhost/integrity-test/tampered:latest "$registry/containers/tampered:latest" >/dev/null 2>&1
container="$registry/containers/tampered@$(cat "$work/container.digest")"

# An index of platforms containing good, which must be refused.
index=localhost/integrity-test/good-index
podman manifest rm "$index" >/dev/null 2>&1 || true
podman manifest create "$index" >/dev/null
podman manifest add "$index" containers-storage:localhost/integrity-test/good:latest >/dev/null
podman manifest push --all --tls-verify=false --digestfile "$work/good-index.digest" \
  "$index" "docker://$registry/apps/good-index:latest" >/dev/null 2>&1
podman manifest rm "$index" >/dev/null
good_index="$registry/apps/good-index@$(cat "$work/good-index.digest")"

# A signing key, as the signing-key workspace would hold it.
podman run --rm -v "$work/key:/key:Z" -w /key -e COSIGN_PASSWORD=test \
  --entrypoint cosign "$COSIGN_IMAGE" generate-key-pair >/dev/null 2>&1
printf test > "$work/key/cosign.password"

yq() { podman run --rm -i "$YQ_IMAGE" "$1" < "$root/tekton/$2"; }

# run_task TASK_FILE [PODMAN_ARGS...]: run each step script of the Task in the step's image,
# with the interpreter on its #! line as Tekton does, and $(results.NAME.path) pointing at
# /work/NAME. Stops at the first failing step and returns its exit code.
run_task() {
  local task=$1 steps i image shell
  shift
  if [[ ! -f $root/tekton/$task ]]; then
    echo "missing tekton/$task" >&2
    exit 2
  fi
  steps=$(yq '.spec.steps | length' "$task")
  for ((i = 0; i < steps; i++)); do
    image=$(yq ".spec.steps[$i].image" "$task")
    yq ".spec.steps[$i].script" "$task" |
      sed 's|$(results.\([A-Z_]*\).path)|/work/\1|g' > "$work/work/step.sh"
    shell=$(head -n 1 "$work/work/step.sh" | sed 's/^#!//')
    echo "--- $task step $i ($image)" >> "$log"
    podman run --rm --network host -v "$repo:/checkout:ro,Z" -v "$work/work:/work:Z" \
      -v "$work/key:/key:ro,Z" -v "$work/registries.conf:/etc/containers/registries.conf:ro,Z" \
      -e CHECKOUT=/checkout/. "$@" --entrypoint "$shell" "$image" /work/step.sh \
      >> "$log" 2>&1 || return $?
  done
}

find_base() { # find_base IMAGE APPROVED_BASES_FILE
  run_task bootc-find-base-task.yaml -e "IMAGE=$1" -e "APPROVED_BASES=signing/.work/verify/$2" \
    -e DOCKERCONFIG_BOUND=false
}

sign() { # sign IMAGE TEST_OUTPUT
  run_task bootc-sign-image-task.yaml -e "IMAGE=$1" -e "BASE_IMAGE=$base" -e "TEST_OUTPUT=$2" \
    -e POLICY_REVISION=test-commit -e KEY= -e KEY_DIR=/key -e DOCKER_CONFIG= \
    -e DOCKERCONFIG_BOUND=false -e "COSIGN_OPTS=--allow-http-registry --allow-insecure-registry"
}

revoke() { # revoke IMAGE FIND_BASE_STATUS CHECK_STATUS
  run_task bootc-revoke-signature-task.yaml -e "IMAGE=$1" -e "FIND_BASE_STATUS=$2" \
    -e "CHECK_STATUS=$3" -e DOCKER_CONFIG= \
    -e "COSIGN_OPTS=--allow-http-registry --allow-insecure-registry"
}

# The host's view: signature-policy/, pointed at the local registry and test key.
sed "s|registry.example.com/|$registry/|g; s|/etc/pki/containers/verifier.pub|/key/cosign.pub|" \
  "$root/signature-policy/rootfs/etc/containers/policy.json" > "$work/host/policy.json"
sed "s|registry.example.com|$registry|" \
  "$root/signature-policy/rootfs/etc/containers/registries.d/registry.example.com.yaml" \
  > "$work/host/registries.d/local.yaml"

host_pull() {
  podman run --rm --network host -v "$work/host:/host:ro,Z" -v "$work/key:/key:ro,Z" \
    -v "$work/registries.conf:/etc/containers/registries.conf:ro,Z" --entrypoint skopeo \
    "$SKOPEO_IMAGE" --policy /host/policy.json --registries.d /host/registries.d \
    copy "docker://$1" dir:/tmp/image >> "$log" 2>&1
}

failed=0
n=0
start() { n=$((n + 1)); log="$work/logs/$n.log"; : > "$log"; name=$1; }
pass() { echo "PASS  $name"; }
fail() { echo "FAIL  $name (see $log)"; failed=1; }
expect_ok() { if "$@"; then pass; else fail; fi; }
# expect_refused REASON COMMAND...: COMMAND fails, and its log says why.
expect_refused() {
  local reason=$1
  shift
  if ! "$@" && grep -qF -- "$reason" "$log"; then pass; else fail; fi
}

printf '# test list\n%s\n' "$base" > "$work/approved.txt"
printf '%s\n' "$good" > "$work/approved-other.txt"

start "find-base identifies the base of good"
if find_base "$good" approved.txt && [[ $(cat "$work/work/BASE_IMAGE") == "$base" ]]; then
  pass; else fail; fi

start "find-base refuses an image with no approved base"
expect_refused "no approved base matches" find_base "$tampered" approved-other.txt

start "find-base refuses a tag"
expect_refused "is not pinned by digest" find_base "$registry/apps/good:latest" approved.txt

start "find-base refuses an index of platforms"
expect_refused "is an index of several platforms" find_base "$good_index" approved.txt

start "sign refuses a failed result, even with a nested SUCCESS"
expect_refused "integrity result is 'FAILURE'" \
  sign "$tampered" '{"result":"FAILURE","failures":3,"nested":{"result":"SUCCESS"}}'

start "sign refuses a tag"
expect_refused "is not pinned by digest" sign "$registry/apps/good:latest" '{"result":"SUCCESS","failures":0}'

start "sign refuses an index of platforms"
expect_refused "is an index of several platforms" sign "$good_index" '{"result":"SUCCESS","failures":0}'

start "sign signs and attests a passing image (pretty-printed result)"
expect_ok sign "$good" $'{\n  "result": "SUCCESS",\n  "failures": 0\n}'

start "host accepts the signed image"
expect_ok host_pull "$good"

start "host refuses the unsigned image"
expect_refused "signature was required" host_pull "$tampered"

start "host accepts an unsigned image from the containers namespace"
expect_ok host_pull "$container"

start "attestation records the base image"
if podman run --rm --network host -v "$work/key:/key:ro,Z" --entrypoint sh "$COSIGN_IMAGE" -c \
  "cosign verify-attestation --key /key/cosign.pub --type urn:bootc-image-integrity:result:v1 \
     --insecure-ignore-tlog --allow-http-registry --allow-insecure-registry $good |
   head -n 1 | sed 's/.*\"payload\":\"\([^\"]*\)\".*/\1/' | base64 -d" >> "$log" 2>&1 &&
  grep -qF "\"baseImage\":\"$base\"" "$log"; then pass; else fail; fi

start "revoke leaves a passing image signed"
if revoke "$good" Succeeded Succeeded && host_pull "$good"; then pass; else fail; fi

start "revoke removes the signature when verification fails"
if revoke "$good" Failed None; then
  expect_refused "signature was required" host_pull "$good"
else
  fail
fi

exit $failed
