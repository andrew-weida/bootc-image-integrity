# Verifying and signing bootc images

When application image pipelines can't be expected to run the
[integrity check](../integrity/), run it centrally for every pushed image, sign the images
that pass, and make hosts accept only signed images. An image that skipped verification
then never gets signed, so it can't be booted.

## Open source projects used

| Project | What it is | Used for |
|---|---|---|
| [skopeo](https://github.com/podman-container-tools/skopeo) | Inspects container images in registries without pulling them | Reading manifests and layer digests to find an image's approved base |
| [cosign](https://github.com/sigstore/cosign) | Signs and verifies container images and attestations | Signing images that pass, attaching the result as an attestation, and removing signatures when approval is withdrawn |

## How it works

```
base image pipeline ──▶ registry: os/base    (signed with the base key)
app pipelines ────────▶ registry: apps/...
                               │ webhook on push
                               ▼
          signing/tekton/bootc-verify-and-sign-pipeline.yaml (owned by the security team)
            find-base ─▶ bootc-image-integrity ─▶ sign + attest
                                                  (failure: revoke)
                               │
                               ▼
          hosts: policy.json requires the verifier's signature for apps/...
```

[tekton/bootc-verify-and-sign-pipeline.yaml](tekton/bootc-verify-and-sign-pipeline.yaml) takes the pushed
image and runs:

1. **find-base** ([tekton/bootc-find-base-task.yaml](tekton/bootc-find-base-task.yaml),
   [scripts/find-base.sh](scripts/find-base.sh)): first checks, with
   [check-ref.sh](../integrity/scripts/check-ref.sh), that the image is pinned by digest and is
   a single image rather than an index of platforms. It then works out which approved base
   the image was built `FROM` by comparing layers. It doesn't use labels, because the
   image's authors set those. The approved bases are listed by digest in
   [approved-bases.txt](approved-bases.txt). An image with no matching base fails: it was
   built on something else, or squashed or rechunked.
2. **check**: the integrity check,
   [../integrity/tekton/bootc-image-integrity-task.yaml](../integrity/tekton/bootc-image-integrity-task.yaml),
   with `FAIL_ON_VIOLATION=true`.
3. **sign** ([tekton/bootc-sign-image-task.yaml](tekton/bootc-sign-image-task.yaml),
   [scripts/sign-image.sh](scripts/sign-image.sh)): checks again for itself before
   signing. [scripts/check-result.py](scripts/check-result.py) parses the result and
   requires `SUCCESS` or `WARNING` with zero failures, and `check-ref.sh` requires a single
   image pinned by digest. It then attaches an attestation recording the base, the policy
   commit and the result, and signs the image with cosign.
4. **revoke**, when find-base or check failed
   ([tekton/bootc-revoke-signature-task.yaml](tekton/bootc-revoke-signature-task.yaml)): removes any
   earlier signatures and attestations of the image, so hosts stop accepting it.

**Multi-platform images:** sign each platform's image digest, not the index. Hosts
verify the signature of their own platform's manifest, and the check covers one image.
List per-platform digests in `approved-bases.txt` too.

### Withdrawing approval

A signature doesn't expire, so approval would otherwise outlive a retired base or an
expired exception. Re-run the pipeline on every signed image regularly. When an image
no longer passes, because its base was removed from `approved-bases.txt` or an exception it
relied on has expired, the revoke task deletes its signatures. Hosts then refuse new
installs and upgrades to it. Hosts already running it keep running it, so compare
`bootc status --json` from your hosts against the signed images as well.

A check that fails for any reason, including an unreachable registry, removes the
signature. Re-run the pipeline to restore it. The verifier needs permission to delete
tags in the application repositories.

### Setting it up

1. **Trigger the pipeline on every push.** Use a registry webhook through Tekton Triggers,
   mapping the pushed image's digest to `IMAGE`. The webhook payload depends on your
   registry. Also re-run it on a schedule for every signed image (see "Withdrawing
   approval") and for anything the webhook missed.
2. **Create the signing key** with `cosign generate-key-pair`, or keep it in a KMS with
   `cosign generate-key-pair --kms awskms://...` and pass the URI as `SIGNING_KEY`. Store a
   key file as a Secret holding `cosign.key` and `cosign.password`, bound to the
   `signing-key` workspace. Only this pipeline should be able to read it.
3. **Ship the host policy in the base image.** Copy
   [signature-policy/rootfs/](signature-policy/rootfs/) into the base image
   (`COPY signing/signature-policy/rootfs/ /`), replace `registry.example.com` with your registry,
   and add both public keys under `/etc/pki/containers/`: `base.pub` for the base image
   and `verifier.pub` for the verification pipeline. bootc then refuses `bootc upgrade` and
   `bootc switch` to unsigned images. For first installs, use
   `bootc install --enforce-container-sigpolicy`. If the hosts also run application
   containers, see "Running application containers on the hosts".
4. **Keep [approved-bases.txt](approved-bases.txt) current** from the base image pipeline.
   Removing an old base stops images built on it from being signed, so teams have to
   rebuild.

The integrity check's [example configuration](../integrity/data/protected.yaml) protects
`/etc/containers/policy.json` and seals
`/etc/containers/registries.d/` and `/etc/pki/containers/`, so an application image can't
weaken the rule that its successors must be signed.

### Signature format

Signatures are stored as a `sha256-<digest>.sig` tag next to the image, the format
containers/image (and so bootc and podman) verifies. cosign 3 defaults to a newer format
that bootc reports as "no signature exists", so `sign-image.sh` passes
`--new-bundle-format=false`. cosign marks that option deprecated; keep the cosign image
pinned until containers/image supports the new format. No transparency log is used: hosts
verify against the public key alone.

The attestation's predicate type is `urn:bootc-image-integrity:result:v1`:

```json
{"image": "registry.example.com/apps/app@sha256:…",
 "baseImage": "registry.example.com/os/base@sha256:…",
 "policyRevision": "<commit>",
 "result": {"result": "SUCCESS", "failures": 0, …}}
```

Read it with `cosign verify-attestation --key verifier.pub --type
urn:bootc-image-integrity:result:v1 --insecure-ignore-tlog IMAGE`.

### Host policy notes

- `policy.json` rejects anything it doesn't list. Add entries for any other registry the
  hosts pull from.
- `containers-storage` is accepted, for images already on the host. Only root can put an
  image there, and root can change the policy anyway.

### Running application containers on the hosts

`policy.json` applies to everything on the host that pulls images, not only to bootc, so
podman refuses unsigned application containers too. The example policy accepts unsigned
images from one namespace, `registry.example.com/containers`:

```json
"registry.example.com/containers": [{"type": "insecureAcceptAnything"}]
```

- **Keep the OS images and the container images in separate namespaces.** The policy
  matches by repository path prefix, so it can't tell them apart within one path. If they
  must share a path, list each container repository on its own line instead.
- **Keep the scope narrow.** Don't accept a whole registry, and leave `default` as
  `reject` so registries you haven't listed stay refused.
- **A per-user policy is another option** for containers that run rootless under a service
  account. podman prefers `~/.config/containers/policy.json` over the system policy, so
  that account can be permissive without affecting bootc. It doesn't work for root, whose
  copy overrides the system policy for bootc as well; the example integrity configuration
  seals `/var/roothome/.config/containers/` for that reason.
- **`registries.d` needs no change.** `use-sigstore-attachments: true` only says where to
  look for signatures. Whether one is required comes from `policy.json`.
- **Adding a namespace means a new base image,** because the integrity check protects
  `policy.json` and application teams can't change it.

Unsigned containers aren't covered by this verification. What they can do depends on how
they run:

- A Quadlet `.container` file starts any image as root, with any options, including
  `--privileged`. The example integrity configuration seals `/etc/containers/systemd/`
  and `/usr/share/containers/systemd/`, the directories Quadlet reads, so application
  teams can't ship them in the OS image. Move those directories to `appendable_dirs` or
  add exceptions if your teams need Quadlets.
- Sealing them is not a boundary. A service unit that runs `podman run --privileged`
  does the same, and application teams can ship their own service units. If application
  teams aren't trusted with root on the host, run their containers rootless and
  unprivileged, and add runtime checks.

## Tests

```bash
../integrity/test/run-e2e.sh   # builds the test images this test uses
test/run-verify-locally.sh     # runs the find-base, sign and revoke Tasks, then checks as a host
```

`run-verify-locally.sh` needs podman. It pushes the integrity check's test images to a
temporary local registry, runs each Task's steps in their images, and checks the result
with [signature-policy/](signature-policy/) the way a host would.
