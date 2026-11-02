#!/usr/bin/env python3
"""Reduce two syft-json documents (base image, derived image) to the policy input.

The policy only needs, per image: the layer list, each file's metadata keyed by path,
and the files each RPM owns. Dropping everything else keeps the input small enough for
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


def flatten(doc, ref):
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
        sys.exit("no file metadata in syft output; set SYFT_FILE_METADATA_SELECTION=all")

    packages = {}
    for artifact in doc.get("artifacts") or []:
        if artifact.get("type") != "rpm":
            continue
        owned = (artifact.get("metadata") or {}).get("files") or []
        packages.setdefault(artifact["name"], []).extend(f["path"] for f in owned)

    layers = [layer["digest"] for layer in doc["source"]["metadata"].get("layers") or []]
    return {
        "ref": ref,
        "repository": repository(ref),
        "layers": layers,
        "files": files,
        "packages": packages,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", required=True, help="syft-json of the base image")
    parser.add_argument("--image", required=True, help="syft-json of the derived image")
    parser.add_argument("--base-ref", default="", help="base image reference, for reporting")
    parser.add_argument("--image-ref", required=True, help="derived image reference; exceptions match its repository")
    args = parser.parse_args()

    with open(args.base) as f:
        base = flatten(json.load(f), args.base_ref)
    with open(args.image) as f:
        image = flatten(json.load(f), args.image_ref)
    json.dump({"base": base, "image": image}, sys.stdout, separators=(",", ":"))


if __name__ == "__main__":
    main()
