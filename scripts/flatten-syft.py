#!/usr/bin/env python3
"""Reduce two syft-json documents (base image, derived image) to the policy input.

The policy only needs, per image: the layer list, each file's metadata keyed by path,
and each RPM's files and version. Dropping everything else keeps the input small enough for
OPA to evaluate a full bootc image comfortably.

usage: flatten-syft.py --base BASE.syft.json --image IMAGE.syft.json --image-ref REF > input.json

Syft must run with file metadata and sha256 digests enabled:
    SYFT_FILE_METADATA_SELECTION=all SYFT_FILE_METADATA_DIGESTS=sha256
"""
import argparse
import json
import sys


def repository(ref):
    """registry.example.com/team/app:tag@sha256:... -> registry.example.com/team/app"""
    name = ref.split("@", 1)[0]
    head, _, last = name.rpartition("/")
    if ":" in last:
        last = last.split(":", 1)[0]
    return f"{head}/{last}" if head else last


def check_digest(doc, ref, label):
    """Exit unless the inventory was scanned from the digest in ref, if ref has one.

    Guards against a reused inventory (BASE_SYFT_JSON) of a different image.
    """
    if "@sha256:" not in ref:
        return
    digest = ref.rsplit("@", 1)[1]
    meta = doc.get("source", {}).get("metadata") or {}
    scanned = [meta.get("userInput", ""), meta.get("manifestDigest", "")] + (meta.get("repoDigests") or [])
    if not any(digest in s for s in scanned if s):
        sys.exit(f"{label} inventory was scanned from {meta.get('userInput') or 'an unknown source'}, not {ref}")


def flatten(doc, ref, label):
    check_digest(doc, ref, label)
    files = {}
    for entry in doc.get("files") or []:
        location = entry["location"]
        meta = entry.get("metadata") or {}
        sha256 = next(
            (d["value"] for d in entry.get("digests") or [] if d.get("algorithm") == "sha256"),
            "",
        )
        files[location["path"]] = {
            "type": meta.get("type", ""),
            "mode": meta.get("mode"),
            "uid": meta.get("userID"),
            "gid": meta.get("groupID"),
            "sha256": sha256,
            "link": meta.get("linkDestination", ""),
            "layer": location.get("layerID", ""),
        }
    if not files:
        sys.exit(f"no file metadata in {label} inventory; set SYFT_FILE_METADATA_SELECTION=all")
    if not any(f["sha256"] for f in files.values() if f["type"] == "RegularFile"):
        sys.exit(f"no sha256 digests in {label} inventory; set SYFT_FILE_METADATA_DIGESTS=sha256")

    packages = {}
    versions = {}
    for artifact in doc.get("artifacts") or []:
        if artifact.get("type") != "rpm":
            continue
        owned = (artifact.get("metadata") or {}).get("files") or []
        packages.setdefault(artifact["name"], []).extend(f["path"] for f in owned)
        versions.setdefault(artifact["name"], set()).add(artifact.get("version", ""))
    if not packages:
        sys.exit(f"no RPM packages in {label} inventory; is it a bootc image?")

    layers = [layer["digest"] for layer in doc["source"]["metadata"].get("layers") or []]
    return {
        "ref": ref,
        "repository": repository(ref),
        "layers": layers,
        "files": files,
        "packages": packages,
        "versions": {name: sorted(v) for name, v in versions.items()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", required=True, help="syft-json of the base image")
    parser.add_argument("--image", required=True, help="syft-json of the derived image")
    parser.add_argument("--base-ref", default="", help="base image reference, for reporting")
    parser.add_argument("--image-ref", required=True, help="derived image reference; exceptions match its repository")
    args = parser.parse_args()

    with open(args.base) as f:
        base = flatten(json.load(f), args.base_ref, "base")
    with open(args.image) as f:
        image = flatten(json.load(f), args.image_ref, "image")
    json.dump({"base": base, "image": image}, sys.stdout, separators=(",", ":"))


if __name__ == "__main__":
    main()
