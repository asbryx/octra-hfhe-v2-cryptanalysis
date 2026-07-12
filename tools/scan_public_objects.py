#!/usr/bin/env python3
"""Scan public Git objects for the missing LPN producer or active secret material."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

NAME_MARKERS = ("sk.bin", "plaintext", "private", "secret", "lpn", "generator", "generate", "sample")
CONTENT_MARKERS = (
    b"lpn_samples",
    b"public_T_hex",
    b"octra-bounty-target-seed-lpn-ay-v1",
    b"lpn_s_bits",
    b"prf_k",
    b"plaintext.txt",
    b"sk.bin",
    b"write.*jsonl",
)


def git(repo: Path, *args: str, text: bool = True) -> str | bytes:
    return subprocess.check_output(["git", *args], cwd=repo, text=text, stderr=subprocess.DEVNULL)


def self_check() -> None:
    assert any(marker in "source/tools/lpn_sample_generator.cpp" for marker in NAME_MARKERS)
    assert any(marker in b"write lpn_samples" for marker in CONTENT_MARKERS)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo", type=Path)
    parser.add_argument("--out", type=Path, default=Path(__file__).with_name("public_object_scan.json"))
    args = parser.parse_args()
    self_check()

    refs = git(args.repo, "for-each-ref", "--format=%(refname) %(objectname)").splitlines()
    unreachable = [
        line.split()[-1]
        for line in git(args.repo, "fsck", "--full", "--no-reflogs", "--unreachable").splitlines()
        if line.startswith("unreachable ")
    ]
    objects = set(git(args.repo, "rev-list", "--objects", "--all").splitlines())
    object_names: dict[str, set[str]] = {}
    for line in objects:
        oid, _, name = line.partition(" ")
        object_names.setdefault(oid, set()).add(name)
    for oid in unreachable:
        object_names.setdefault(oid, set()).add("")

    findings = []
    scanned_blobs = skipped_large = 0
    for oid, names in sorted(object_names.items()):
        try:
            kind = git(args.repo, "cat-file", "-t", oid).strip()
        except subprocess.CalledProcessError:
            continue
        if kind != "blob":
            continue
        size = int(git(args.repo, "cat-file", "-s", oid).strip())
        suspicious_name = any(marker in name.lower() for name in names for marker in NAME_MARKERS)
        if size > 2_000_000 and not suspicious_name:
            skipped_large += 1
            continue
        raw = git(args.repo, "cat-file", "blob", oid, text=False)
        scanned_blobs += 1
        lower = raw.lower()
        markers = [marker.decode("ascii") for marker in CONTENT_MARKERS if marker.lower() in lower]
        if suspicious_name or markers:
            findings.append({
                "oid": oid,
                "names": sorted(name for name in names if name),
                "size": size,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "content_markers": markers,
            })

    producer_candidates = [
        finding for finding in findings
        if any(
            not name.startswith("lpn_samples/")
            and not name.endswith(".jsonl")
            and ("generator" in name.lower() or "generate" in name.lower())
            for name in finding["names"]
        )
        or (
            "octra-bounty-target-seed-lpn-ay-v1" in finding["content_markers"]
            and any(not name.endswith(".jsonl") for name in finding["names"])
        )
    ]
    secret_candidates = [
        finding for finding in findings
        if any(name.lower().endswith(("sk.bin", "plaintext.txt")) for name in finding["names"])
    ]
    result = {
        "repo": args.repo.as_posix(),
        "refs": refs,
        "unreachable_objects": len(unreachable),
        "named_objects": len(object_names),
        "scanned_blobs": scanned_blobs,
        "skipped_large_non_suspicious_blobs": skipped_large,
        "findings": findings,
        "producer_candidates": producer_candidates,
        "secret_candidates": secret_candidates,
        "verdict": "REVIEW" if producer_candidates or secret_candidates else "NO_PUBLIC_LPN_PRODUCER_OR_ACTIVE_SECRET_FOUND",
        "limitation": "Unreachable objects are local object-cache evidence; public availability is established only for fetched refs/history.",
    }
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "verdict": result["verdict"],
        "refs": len(refs),
        "unreachable_objects": len(unreachable),
        "scanned_blobs": scanned_blobs,
        "findings": len(findings),
        "producer_candidates": len(producer_candidates),
        "secret_candidates": len(secret_candidates),
    }, indent=2))


if __name__ == "__main__":
    main()
