# bootc image integrity

Checks that a bootc image built `FROM` a hardened base image leaves intact what the base
protects (security agents, hardening config, the container signature policy, etc), and
optionally signs the images that pass so hosts run nothing else.

The repository has two parts:

| Directory | What it does 
|---|---|
| [integrity/](integrity/) | Compares an image with its base and reports anything it changes, removes, overrides or shadows. Runs locally or as a Tekton Task.
| [signing/](signing/) | Runs the integrity check centrally for every pushed image, signs the images that pass, withdraws signatures that no longer hold. It includes an example host policy that the base image must carry so host accept only signed images. 

```
.
├── integrity/                  the check and its report
│   ├── policy/, data/          the rules and what they protect
│   ├── scripts/                scan, flatten, report
│   ├── tekton/                 the check as a Task
│   └── test/                   unit and end-to-end tests
└── signing/                    verification and signing
    ├── approved-bases.txt      the bases images may be built FROM
    ├── scripts/                find the base, check the result, sign
    ├── tekton/                 find-base, sign and revoke Tasks, and the pipeline
    ├── signature-policy/       the host's policy.json and registries.d
    └── test/                   local end-to-end test
```
