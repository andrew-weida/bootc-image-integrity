#!/bin/sh
# Sign IMAGE with cosign after it passed the integrity check, and attach the result as an
# attestation recording the base, the policy revision and the findings.
#
# usage: sign-image.sh IMAGE BASE_IMAGE POLICY_REVISION TEST_OUTPUT_FILE
#   IMAGE             by digest; a tag is refused, because it could move after the check
#   TEST_OUTPUT_FILE  the TEST_OUTPUT written by report.py. Validate it with
#                     check-result.py first, and IMAGE with check-ref.sh.
# Environment:
#   COSIGN_KEY       a key file, or a KMS URI such as awskms://... or hashivault://...
#   COSIGN_PASSWORD  the key file's password
#   COSIGN_OPTS      extra options for cosign, e.g. --allow-insecure-registry
#
# Signatures use cosign's older format, a sha256-<digest>.sig tag next to the image,
# because that is the format containers/image (and so bootc and podman) verifies. cosign 3
# defaults to a newer format that bootc reports as "no signature exists". No transparency
# log is used; hosts verify against the public key alone.
set -eu

if [ $# -ne 4 ]; then
  sed -n '2,18p' "$0" >&2
  exit 2
fi
image=$1
base=$2
revision=$3
result_file=$4

for ref in "$image" "$base"; do
  if ! echo "$ref" | grep -Eq '^[^@[:space:]]+@sha256:[0-9a-f]{64}$'; then
    echo "not signing: $ref is not pinned by digest" >&2
    exit 1
  fi
done
result=$(cat "$result_file")

legacy="--use-signing-config=false --tlog-upload=false --new-bundle-format=false"
predicate_type=urn:bootc-image-integrity:result:v1
predicate=$(mktemp)
printf '{"image":"%s","baseImage":"%s","policyRevision":"%s","result":%s}\n' \
  "$image" "$base" "$revision" "$result" > "$predicate"

# Attest first, so a signed image always has its attestation.
# shellcheck disable=SC2086 # $legacy and COSIGN_OPTS are lists of options
cosign attest --yes --key "$COSIGN_KEY" $legacy ${COSIGN_OPTS:-} \
  --type "$predicate_type" --predicate "$predicate" "$image"
# shellcheck disable=SC2086
cosign sign --yes --key "$COSIGN_KEY" $legacy ${COSIGN_OPTS:-} "$image"
