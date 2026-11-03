#!/usr/bin/env bash
# Run tekton/bootc-image-integrity-task.yaml's steps with podman instead of a cluster: each step's command or
# script runs in the step's image, with the Task's environment and a shared /work volume.
# The images come from a throwaway local registry, so test/run-e2e.sh must have built them.
#
# usage: test/run-task-locally.sh [IMAGE_NAME]   (default: tampered)
# Prints the report step's output and the TEST_OUTPUT result; exits with the report's code.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work="$root/.work/task-local"
name=${1:-tampered}
registry=localhost:5001
YQ_IMAGE=docker.io/mikefarah/yq:4
REGISTRY_IMAGE=docker.io/library/registry:2

rm -rf "$work"
mkdir -p "$work/work"

podman run -d --rm --name integrity-registry -p 5001:5000 "$REGISTRY_IMAGE" >/dev/null
trap 'podman stop integrity-registry >/dev/null' EXIT
until curl -fs "http://$registry/v2/" >/dev/null; do sleep 0.2; done

push() {
  podman push --tls-verify=false --digestfile "$work/$1.digest" \
    "localhost/integrity-test/$1:latest" "$registry/integrity-test/$1:latest" >/dev/null 2>&1
  echo "$registry/integrity-test/$1@$(cat "$work/$1.digest")"
}
base_image=$(push base)
image=$(push "$name")

yq() { podman run --rm -i "$YQ_IMAGE" "$@" < "$root/tekton/bootc-image-integrity-task.yaml"; }

env_args=(
  -e "IMAGE=$image" -e "BASE_IMAGE=$base_image" -e CHECKOUT=/checkout/.
  -e FAIL_ON_VIOLATION=true -e DOCKER_CONFIG= -e HOME=/work -e TMPDIR=/work
  -e SYFT_FILE_METADATA_SELECTION=all -e SYFT_FILE_METADATA_DIGESTS=sha256
  -e SYFT_CHECK_FOR_APP_UPDATE=false
  -e SYFT_REGISTRY_INSECURE_USE_HTTP=true -e SKOPEO_OPTS=--tls-verify=false # local registry only
)
mounts=(-v "$work/work:/work:Z" -v "$root:/checkout:ro,Z")

rc=0
steps=$(yq '.spec.steps | length')
for ((i = 0; i < steps; i++)); do
  step=$(yq ".spec.steps[$i].name")
  step_image=$(yq ".spec.steps[$i].image")
  script=$(yq ".spec.steps[$i].script // \"\"")
  if [[ -n "$script" ]]; then
    sed 's|$(results.TEST_OUTPUT.path)|/work/TEST_OUTPUT|g' <<<"$script" > "$work/work/step.sh"
    podman run --rm --network host "${env_args[@]}" "${mounts[@]}" -w /work \
      --entrypoint /bin/sh "$step_image" /work/step.sh > "$work/$step.log" 2>&1 || rc=$?
  else
    args=()
    while IFS= read -r arg; do
      args+=("$arg")
    done < <(yq ".spec.steps[$i].args[]" |
      sed "s|\$(params.BASE_IMAGE)|$base_image|; s|\$(params.IMAGE)|$image|")
    podman run --rm --network host "${env_args[@]}" "${mounts[@]}" \
      --entrypoint "$(yq ".spec.steps[$i].command[0]")" "$step_image" "${args[@]}" \
      > "$work/$step.log" 2>&1 || rc=$?
  fi
  echo "step $step: exit $rc"
  if [[ $rc -ne 0 ]]; then
    [[ $step == report ]] || cat "$work/$step.log"
    break
  fi
done

if [[ -f "$work/report.log" ]]; then
  cat "$work/report.log"
fi
if [[ -f "$work/work/TEST_OUTPUT" ]]; then
  echo "TEST_OUTPUT: $(cat "$work/work/TEST_OUTPUT")"
fi
exit $rc
