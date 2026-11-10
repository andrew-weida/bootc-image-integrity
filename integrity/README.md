# bootc image integrity check

Checks that a bootc image built `FROM` a hardened base image leaves intact what the base
protects (security agents, hardening config, the container signature policy) and reports
anything it changes, removes, overrides or shadows.

This directory is self-contained. [../signing/](../signing/) builds on it to verify and
sign every image centrally.

```
syft (base) ──┐
              ├─ scripts/flatten-syft.py ─ conftest (policy/ + data/) ─ scripts/report.py
syft (image) ─┘
```

1. **syft** inventories both images: every file's type, mode, owner, sha256, symlink
   target, and the layer it came from, plus the files each RPM owns.
2. **flatten-syft.py** reduces the two inventories to the policy input.
3. **conftest** evaluates [policy/integrity.rego](policy/integrity.rego) against the
   configuration in [data/](data/).
4. **report.py** prints the findings, writes a `TEST_OUTPUT` result, and sets the exit code.

## Open source projects used

| Project | What it is | Used for |
|---|---|---|
| [syft](https://github.com/anchore/syft) | SBOM generator for container images and file systems | Inventorying each image's files (type, mode, owner, sha256, layer) and the files each RPM owns |
| [conftest](https://github.com/open-policy-agent/conftest) | Runs [Open Policy Agent](https://github.com/open-policy-agent/opa) Rego policies against structured data | Evaluating [policy/integrity.rego](policy/integrity.rego) against the flattened inventories; `conftest verify` runs the unit tests |
| [skopeo](https://github.com/podman-container-tools/skopeo) | Inspects container images in registries without pulling them | Rejecting tags and multi-platform indexes before the Task scans ([scripts/check-ref.sh](scripts/check-ref.sh)) |

## What it catches

Every protected path must look exactly as it does in the base image. "Absent" counts as
a state, so a protected path the base doesn't have must stay absent. That rules out four
ways a derived build can weaken the base.

### Changing

A protected file is still there but differs from the base: content, permissions, owner,
or symlink target.

```dockerfile
RUN chmod 666 /etc/ssh/sshd_config.d/00-hardening.conf
```

Reported as `modified … changed mode`. A file rewritten with identical content is
reported as `touched`.

### Removing

A protected file is gone, whether by `rm`, `rpm -e`, or a command that deletes files as a
side effect.

```dockerfile
RUN systemctl disable auditd
```

This deletes the base's `/etc/systemd/system/multi-user.target.wants/auditd.service`
symlink, so auditd no longer starts. Reported as `deleted`.

### Overriding

The protected file is untouched, but a new file adds settings that take precedence over
it. Overrides are caught only where the configuration looks: sealed and appendable
directories, protected paths, and the drop-in directories derived for protected systemd
units.

```dockerfile
RUN mkdir -p /etc/systemd/system/auditd.service.d && \
    printf '[Service]\nExecStart=\nExecStart=/bin/true\n' \
      > /etc/systemd/system/auditd.service.d/override.conf
```

The drop-in clears `ExecStart=` and replaces it, so auditd's unit file is never used as
written. Reported as `added`, because drop-in directories of protected units are sealed.

A drop-in can also apply to every service at once:

```dockerfile
RUN mkdir -p /etc/systemd/system/service.d && \
    printf '[Service]\nEnvironment=LD_PRELOAD=/opt/app/lib/hook.so\n' \
      > /etc/systemd/system/service.d/10-app.conf
```

This loads the app's library into every systemd service, including the security agent,
without touching any of their unit files. Reported as `added`, because
`/etc/systemd/system/service.d/` is sealed.

### Shadowing

The protected file is untouched, but a new file with the same name sits in a directory
that is searched first, so the original is never read or run.

```dockerfile
RUN ln -s /dev/null /etc/sysctl.d/99-hardening.conf
```

sysctl reads `/etc/sysctl.d/99-hardening.conf` instead of
`/usr/lib/sysctl.d/99-hardening.conf`, and gets nothing. Likewise, a `/usr/local/bin/sshd`
runs instead of `/usr/sbin/sshd` because it comes first in `PATH`. Reported as `added`.
The directory pairs are configured in `shadows`.

### Installing forbidden packages

Separately from the comparison with the base, `forbidden_packages` lists RPMs that must
never be installed.

```dockerfile
RUN dnf install -y telnet
```

Reported as `forbidden telnet`.

### Changing packages and the kernel

`package_changes` reports every RPM whose version differs from the base's, and every RPM
the base has that the image doesn't. It warns by default; set it to `fail` if application
teams must not update system packages.

```dockerfile
RUN dnf -y update
```

Reported as `package openssh-server: version changed from … to …` for each package. The
files of protected packages also change, so those fail as `modified` regardless.

The example configuration seals `/usr/lib/modules/`, which holds the kernel, its initramfs
and its modules. A kernel update is reported as one `added` and one `deleted` finding for
the two kernel directories, because a directory that is new or gone as a whole is reported
once when it has more than 20 entries. An added kernel module is reported on its own.

### Findings

| Finding | Example |
|---|---|
| `modified` | Agent binary replaced, hardening file `chmod 666`, owner changed |
| `deleted` | `rpm -e` or `rm` of a protected package's files; `systemctl disable` of a protected unit |
| `added` | `/etc/ld.so.preload`; a file in a sealed directory; a drop-in for a protected unit |
| `added` (shadow) | `/etc/sysctl.d/99-hardening.conf → /dev/null` masking `/usr/lib/sysctl.d/99-hardening.conf`; `/usr/local/bin/sshd` |
| `added` (name) | `/etc/rsyslog.d/00-app.conf`, whose name sorts ahead of the base's log forwarding |
| `forbidden` | `dnf install telnet` when `telnet` is in `forbidden_packages` |
| `package` | `dnf -y update` changing a package's version; `rpm -e` of a base package. Warns unless `package_changes: fail`. |
| `touched` | Protected file rewritten with the same content. This catches changes syft doesn't record (SELinux labels, file capabilities, other xattrs), but only for layered images (below). |

## Configuration

Conftest loads the YAML files in [data/](data/) as policy data. The two files have separate
top-level keys: `integrity:` in `protected.yaml` and `exceptions:` in `exceptions.yaml`.
Exceptions are not nested under `integrity:`.

### protected.yaml format

[data/protected.yaml](data/protected.yaml) is an example for a hardened RHEL bootc base.
Edit it for your base. Its top-level `integrity` value must be a YAML mapping.

```yaml
integrity:
  require_layered: true
  package_changes: warn
  protected_packages:
    - audit
    - openssh-server
  forbidden_packages:
    - telnet
  protected_files:
    - /etc/containers/policy.json
    - /usr/lib/sysctl.d/99-hardening.conf
  sealed_dirs:
    - /etc/ssh/sshd_config.d/
  appendable_dirs:
    - dir: /etc/rsyslog.d/
      allow: '^[5-9][0-9]-[A-Za-z0-9_.-]+\.conf$'
  shadows:
    /usr/lib/sysctl.d/:
      - /etc/sysctl.d/
```

Each field is optional individually. At least one of `protected_packages`,
`protected_files`, `sealed_dirs`, `appendable_dirs` or `forbidden_packages` must be
non-empty. Setting only `require_layered`, `package_changes` or `shadows` does not meet
that requirement.

| Key | YAML type | Default when omitted | Meaning |
|---|---|---|---|
| `protected_packages` | List of strings | `[]` | Protect files owned by these RPMs that exist in the base inventory. Include libraries your agents load. A listed package absent from the base produces a warning. |
| `package_changes` | String: `fail`, `warn` or `ignore` | `warn` | What to do when a base RPM's version changes or the RPM is removed. This does not relax the file checks for protected packages. |
| `forbidden_packages` | List of strings | `[]` | RPM names that must not be installed. This does not detect binaries copied in without an RPM. |
| `protected_files` | List of strings | `[]` | Exact file paths to preserve. A file path the base lacks must stay absent. Paths are not glob patterns. |
| `sealed_dirs` | List of strings | `[]` | Directories under which nothing may be added, changed or removed, including nested entries. |
| `appendable_dirs` | List of mappings with string fields `dir` and `allow` | `[]` | Preserve base entries; allow new direct children only when their names match the regular expression in `allow`. |
| `shadows` | Mapping of source directory strings to lists of target directory strings | `{}` | For each protected source file, protect the equivalent path in each target directory so it cannot shadow the source. |
| `require_layered` | Boolean: `true` or `false` | `false` | Require the base layers to be an unchanged prefix of the image layers. When false, a mismatch warns and skips `touched` checks; content comparisons still run. The supplied configuration sets this to `true`. |

Use `[]` for an empty list and `{}` for an empty mapping. A key with no value is YAML
`null`, which is not a substitute for either. Keep booleans unquoted.

Path and pattern conventions:

- Use absolute image paths. `sealed_dirs` and `appendable_dirs[].dir` accept directories
  with or without a trailing `/`.
- `appendable_dirs[].allow` is a regular expression applied to the child's name, not its
  full path. Use `^` and `$` to match the whole name. Single-quoted YAML preserves
  backslashes such as `\.`. The example permits `60-app.conf` but rejects `00-app.conf`
  and nested paths such as `60-app/nested.conf`.
- Use trailing `/` on both source and target directories in `shadows`: these strings are
  literal prefixes. The example protects `/etc/sysctl.d/99-hardening.conf` because
  `/usr/lib/sysctl.d/99-hardening.conf` is protected. Shadow paths are generated from
  existing base paths selected by `protected_packages` or `protected_files`; sealing a
  source directory alone does not generate them.

Use appendable directories only where applications need to add files, and choose the
pattern from the tool's precedence rules. For example, rsyslog runs files in name order,
and an earlier rule can discard messages, so application files must sort after the base's.

These are derived automatically from the protected set:

- **Unit overrides:** for every protected unit, a unit of the same name is protected in each directory systemd loads units from (`/etc/systemd/system.control/`, `/etc/systemd/system/`, `/etc/systemd/system.attached/`, `/usr/local/lib/systemd/system/`, `/usr/lib/systemd/system/`), which catches replacing or masking it.
- **Unit drop-in directories:** in each of those directories, every drop-in directory systemd reads for a protected unit is sealed: `<unit>.d/`, one per dash-separated prefix (`falcon-.service.d/` for `falcon-sensor.service`), and the one for every unit of its type (`service.d/`).
- **Template instances:** for a protected template such as `worker@.service`, instance unit files and drop-ins (`worker@one.service`, `worker@one.service.d/`) are watched, and the base's enablement links for its instances are protected.
- **Enablement symlinks:** the base's `*.wants/` and `*.requires/` links for protected units are protected.
- **Redirecting symlinks:** a new symlink at a sealed or appendable directory, or at any directory above a watched path, is reported, because it moves the contents somewhere the check doesn't look. Symlinks the base already has are allowed.

The configuration itself is validated: a missing `integrity:` section, an unknown or mistyped key, or a configuration that protects nothing fails the check instead of silently protecting less.

### exceptions.yaml format

[data/exceptions.yaml](data/exceptions.yaml) contains a top-level `exceptions` list. Use
`exceptions: []` when no deviations are approved; omitting the key also defaults to no
exceptions.

```yaml
exceptions:
  - image: registry.example.com/team-x/app
    path: /etc/sysctl.d/99-team-x.conf
    ticket: SEC-1234
    expires: "2027-03-31"
    reason: Needs net.core.somaxconn above the hardened default.
  - image: registry.example.com/team-x/app
    path: telnet
    ticket: SEC-1235
    expires: "2027-03-31"
    reason: Temporary compatibility requirement.
```

Every entry requires all five fields, and every value must be a string:

| Field | Format | Meaning |
|---|---|---|
| `image` | Exact image repository, without a tag, digest or transport prefix | Matches `registry.example.com/team-x/app` across its tags and digests. Wildcards are not supported here. |
| `path` | Exact finding path or glob | Matches file or directory findings. For a forbidden RPM or a package change treated as a failure, use the package name, such as `telnet`. |
| `ticket` | Approval reference, such as `SEC-1234` | Identifies the approval in warning messages. |
| `expires` | Quoted, valid calendar date in `"YYYY-MM-DD"` format | The exception stops applying at 00:00 UTC on this date, not at the end of the day. Quoting keeps YAML from treating it as a date value instead of a string. |
| `reason` | Explanation of the approved deviation | Records why the deviation is needed. |

Exception matching and results:

- `path` uses glob syntax, not the regular expressions used by `appendable_dirs[].allow`.
  `*` stays within one path component; `**` can cross `/`. For example,
  `/etc/sysctl.d/*.conf` matches direct children, while `/opt/agent/**` can match nested
  paths.
- Exceptions match the path shown in the finding. If a large added or deleted directory
  is reported as one finding, the exception must match that directory path itself.
- An active exception turns a matching failure into a warning. It applies to all finding
  kinds at that path; there is no separate `kind` selector. It cannot waive invalid
  configuration or a `require_layered` failure.
- On the expiry date, a matching violation fails again. Expired entries for the image's
  repository also produce an expiry warning. Entries with missing or non-string fields,
  or an expiry value outside the required date format, are ignored with a warning and
  do not grant an exception.

## Run locally

Requires `syft`, `conftest` and `python3`.

```bash
scripts/check-image.sh \
  registry:registry.example.com/os/base@sha256:... \
  registry:registry.example.com/team/app@sha256:...
```

Environment variables:

| Variable | Effect |
|---|---|
| `DATA_DIRS` | Use other configuration directories. |
| `WORK_DIR` | Keep the intermediate files there. By default they go in a temporary directory that is removed on exit. |
| `BASE_SYFT_JSON` | Reuse an existing syft inventory of the base instead of scanning it again. This saves about a minute per check on a full bootc image when checking several images against one base. The check stops if the inventory wasn't scanned from the requested base digest. |
| `KEEP_SYFT=true` | Keep the syft inventories, which are otherwise deleted after flattening (about 100 MB each for a full bootc image). |

## Tekton

[tekton/bootc-image-integrity-task.yaml](tekton/bootc-image-integrity-task.yaml) runs the same steps.

- **Params:**
  - `IMAGE` and `BASE_IMAGE`, both by digest. The Task fails on a tag, which could move
    after the check, and on an index of platforms, of which syft would scan only one.
  - `CHECKOUT_SUBDIR`: where policy/, data/ and scripts/ are in the workspace; `integrity`
    by default, for a checkout of this repository
  - `FAIL_ON_VIOLATION`
- **Workspaces:**
  - `integrity`: a checkout of this repository
  - `dockerconfig`: optional pull credentials
- **Result:** `TEST_OUTPUT`

```yaml
# Pipeline excerpt. Whoever controls the `integrity` workspace controls the policy, so
# clone it from a repository the application teams cannot push to, at a pinned commit.
tasks:
  - name: fetch-integrity-policy
    taskRef: {name: git-clone}
    params:
      - {name: url, value: https://git.example.com/platform/bootc-image-integrity}
      - {name: revision, value: <commit sha>}
    workspaces:
      - {name: output, workspace: integrity-policy}
  - name: image-integrity
    runAfter: [build-image, fetch-integrity-policy]
    taskRef: {name: bootc-image-integrity}
    params:
      - {name: IMAGE, value: "$(tasks.build-image.results.IMAGE_URL)@$(tasks.build-image.results.IMAGE_DIGEST)"}
      - {name: BASE_IMAGE, value: registry.example.com/os/base@sha256:...}
    workspaces:
      - {name: integrity, workspace: integrity-policy}
```

The step images are pinned by tag. Pin them by digest before production use.

## From syft JSON to policy input

syft produces a general-purpose SBOM. [flatten-syft.py](scripts/flatten-syft.py) reduces
the two inventories to the policy input, `input.json`, which keeps only what the policy
reads. Two things drive this:

- **Size.** OPA loads the whole input into memory. The flattened `input.json` discards uneeded information to reduce the size.

- **Lookup by path.** syft lists files in an array; the policy asks "what does the base
  have at this path?" thousands of times, so files are keyed by path.

### Files

The same file, `/usr/bin/sshd`, in each format. The syft entry is trimmed; the full one
also has ELF details such as imported libraries and stack protection.

```jsonc
// syft JSON: one element of "files"
{
  "id": "16102077dca26d57",
  "location": {"path": "/usr/bin/sshd", "layerID": "sha256:bf9dda24…"},
  "metadata": {"mode": 755, "type": "RegularFile", "userID": 0, "groupID": 0,
               "mimeType": "application/x-sharedlib", "size": 400520},
  "digests": [{"algorithm": "sha256", "value": "02d3f7ee…"}],
  "executable": {"format": "elf", "importedLibraries": ["libcrypto.so.3", …], …}
}
```

```jsonc
// input.json: base.files (or image.files), keyed by path
"/usr/bin/sshd": {"type": "RegularFile", "mode": 755, "uid": 0, "gid": 0,
                  "sha256": "02d3f7ee…", "link": "", "layer": "sha256:bf9dda24…"}
```

| input.json | syft JSON | Used for |
|---|---|---|
| key | `location.path` | Looking up a path in either image |
| `type`, `mode`, `uid`, `gid` | `metadata.type`, `.mode`, `.userID`, `.groupID` | `modified` |
| `sha256` | the `sha256` entry in `digests` | `modified` |
| `link` | `metadata.linkDestination` | `modified`, redirecting symlinks |
| `layer` | `location.layerID` | `touched`, and the layer shown in each finding |

### Packages

The policy only needs to know which paths each protected RPM owns. syft lists every
package it finds (kernel modules, Go modules, Python packages, RPMs) under `artifacts`,
with versions, licenses, CPEs and a full file list. Only RPMs are kept, as name → paths:

```jsonc
// syft JSON: one element of "artifacts" (trimmed)
{"name": "openssh-server", "type": "rpm", "version": "10.2p1-16.fc44",
 "metadata": {"files": [{"path": "/etc/pam.d/sshd", "mode": 33188, "digest": {…}, …}, …], …}}

// input.json: base.packages
"openssh-server": ["/etc/pam.d/sshd", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d", …]
```

The RPM's recorded digests and modes are dropped on purpose: they describe what the
package installed, not what is in the image. The policy compares the files themselves.

### Per image

Each of `base` and `image` also has:

| Field | From | Used for |
|---|---|---|
| `layers` | the `digest` of each `source.metadata.layers` entry | Deciding whether the image is layered on the base |
| `versions` | each RPM artifact's `version`, as name → list of versions | `package` |
| `ref` | the reference passed to the script | Reporting |
| `repository` | `ref` without tag or digest | Matching exceptions |

### Checks before flattening

The script stops instead of producing input that would silently protect less if:

- the inventory wasn't scanned from the digest in the reference, e.g. a stale
  `BASE_SYFT_JSON`
- it has no file metadata (`SYFT_FILE_METADATA_SELECTION=all` not set)
- it has no sha256 digests (`SYFT_FILE_METADATA_DIGESTS=sha256` not set)
- it has no RPMs

## Gotcha's / Limitations

- **Squashed or rechunked images.** `touched` only works when the base's layers appear
  unchanged at the bottom of the image, and squashing or rechunking the derived image
  removes them. With `require_layered: true`, as in the example configuration, such images
  fail. With it off, they only warn, and the check runs without `touched`. The content
  checks still run, because they compare file inventories rather than layers, but changes
  syft doesn't record (SELinux labels, file capabilities, other xattrs) go unnoticed.
- **Paths are compared literally.** An RPM path that reaches the file through a symlinked
  directory isn't found in the base inventory, so it isn't protected. Put the real path in
  `protected_files`.
- **Override coverage is only as complete as the configuration.** Only systemd unit
  overrides are derived automatically. Every other directory where a new file changes
  behaviour must be listed in `sealed_dirs` or `appendable_dirs`. The example seals the
  common ones; `/etc/profile.d/` is deliberately left open, and packages can still add
  files under `/usr/lib/tmpfiles.d/`, `/usr/lib/sysusers.d/` and `/usr/lib/modprobe.d/`
  unless you seal those too.
- **Effective configuration isn't evaluated.** A setting can be weakened through a path
  that isn't protected, for example a new `Include` in an unprotected file. Protect the
  directories each tool reads, or add a runtime check such as `sshd -T`.
- **Build time only.** Running hosts need their own checks.
  [../signing/](../signing/) makes hosts accept only images that passed.

## Tests

From this directory:

```bash
conftest verify --policy policy   # Rego unit tests
test/run-e2e.sh                   # builds images in test/images and checks expected findings
test/run-task-locally.sh tampered # runs tekton/bootc-image-integrity-task.yaml's steps with podman
```

The test scripts need podman. `run-e2e.sh` runs syft and conftest from container images
when they aren't installed.

The test images build from `quay.io/fedora/fedora-bootc:44` (about 2 GB). Both scripts
push them to a temporary local registry, so the base's layers are stored once and discarded
afterwards. `run-task-locally.sh` evaluates against `data/`, not the test configuration,
and expects the images `run-e2e.sh` builds.
