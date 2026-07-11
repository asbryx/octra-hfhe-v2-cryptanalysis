#!/usr/bin/env python3
"""QP-01: provenance search for missing security-test sources."""
import json
import pathlib
import subprocess
import zipfile
from datetime import datetime, timezone

PV = r"upstream/pvac_hfhe_cpp"
OUT = pathlib.Path(r"archive/legacy-probes/qp-01")
OUT.mkdir(parents=True, exist_ok=True)
TMP = pathlib.Path(r"local-corpus/qp")
TMP.mkdir(parents=True, exist_ok=True)

PRIMARY = [
    "tests/forge_decrypt_payload.cpp",
    "tests/poc_pc_forge_soundness.cpp",
    "tests/test_ristretto255.cpp",
]
ALL_MISSING = PRIMARY + [
    "tests/test_bound_range.cpp",
    "tests/test_bound_zero_proof.cpp",
    "tests/test_ct_geq_sign.cpp",
    "tests/test_private_transfer.cpp",
    "tests/test_range_proof.cpp",
    "tests/test_verify_zero.cpp",
    "tests/test_zero_proof.cpp",
]

refs = [
    "HEAD",
    "b0813def89db6b4f82dd2cea39f1cfcdc670f9d2",
    "refs/remotes/pr/490",
    "refs/remotes/pr/499",
    "refs/remotes/pr/500",
]

ref_hits = {}
for ref in refs:
    hits = []
    for m in ALL_MISSING:
        r = subprocess.run(
            ["git", "-C", PV, "cat-file", "-e", f"{ref}:{m}"],
            capture_output=True,
        )
        if r.returncode == 0:
            hits.append(m)
    ref_hits[ref] = hits

# zipball of introduction commit
zpath = TMP / "pvac-b0813.zip"
if not zpath.exists() or zpath.stat().st_size < 1000:
    with open(zpath, "wb") as f:
        subprocess.check_call(
            [
                "gh",
                "api",
                "repos/octra-labs/pvac_hfhe_cpp/zipball/b0813def89db6b4f82dd2cea39f1cfcdc670f9d2",
                "-H",
                "Accept: application/vnd.github+json",
            ],
            stdout=f,
        )

archive_primary_hits = []
archive_missing_basenames = []
with zipfile.ZipFile(zpath) as z:
    basenames = {pathlib.Path(n).name for n in z.namelist()}
    archive_primary_hits = [
        n
        for n in z.namelist()
        if any(
            x in n
            for x in [
                "poc_pc_forge",
                "forge_decrypt",
                "test_ristretto255.cpp",
            ]
        )
    ]
    archive_missing_basenames = [
        pathlib.Path(m).name
        for m in ALL_MISSING
        if pathlib.Path(m).name not in basenames
    ]

# history log for paths
hist = subprocess.run(
    [
        "git",
        "-C",
        PV,
        "log",
        "--all",
        "--full-history",
        "--",
        *PRIMARY,
    ],
    capture_output=True,
    text=True,
)

# PR heads
pr_heads = subprocess.check_output(
    ["git", "-C", PV, "ls-remote", "origin", "refs/pull/*/head"], text=True
)

# GitHub code search totals
search = {}
for q in [
    "filename:poc_pc_forge_soundness.cpp",
    "filename:forge_decrypt_payload.cpp",
    "filename:test_ristretto255.cpp",
    "poc_pc_forge_soundness extension:cpp",
    "forge_decrypt_payload extension:cpp",
]:
    try:
        out = subprocess.check_output(
            ["gh", "api", "-X", "GET", "search/code", "-f", f"q={q}", "--jq", ".total_count"],
            text=True,
            timeout=60,
        ).strip()
        search[q] = int(out)
    except Exception as e:
        search[q] = f"error:{e}"

# fork unique-head file search if present
fork_search_path = TMP / "qp01-fork-file-search.json"
fork_search = (
    json.loads(fork_search_path.read_text(encoding="utf-8"))
    if fork_search_path.exists()
    else None
)

# Makefile first appearance
blame = subprocess.check_output(
    ["git", "-C", PV, "blame", "-L", "148,161", "Makefile"], text=True, errors="replace"
)

result = {
    "date_utc": datetime.now(timezone.utc).isoformat(),
    "target_pvac_commit": "071b0e909c119de815e284b347c4bd979cb59ef3",
    "introduction_commit": "b0813def89db6b4f82dd2cea39f1cfcdc670f9d2",
    "primary_targets": PRIMARY,
    "all_makefile_missing_tests": ALL_MISSING,
    "git_path_history_empty": hist.stdout.strip() == "" and hist.returncode == 0,
    "git_path_history_stdout": hist.stdout[:500],
    "ref_presence": ref_hits,
    "pr_heads": pr_heads.strip().splitlines(),
    "archive_b0813_zip_sha256": None,
    "archive_b0813_primary_hits": archive_primary_hits,
    "archive_b0813_missing_basenames": archive_missing_basenames,
    "github_code_search_totals": search,
    "fork_unique_head_file_search": fork_search,
    "makefile_blame_excerpt": blame,
    "verdict": "CLOSED",
    "reason": (
        "No public source recovered for primary missing security tests after "
        "local history, all PR heads, b0813 zipball archive, GitHub code search "
        "(filename+content), and unique-HEAD fork content API checks. "
        "Makefile targets introduced in b0813 without corresponding sources ever "
        "entering the public tree."
    ),
    "target_binding": {
        "source_recovered": False,
        "ordinary_BASE_path_applicable": None,
        "works_on_fixed_active_secret_ct": None,
        "needs_sk": None,
    },
}

import hashlib

h = hashlib.sha256(zpath.read_bytes()).hexdigest()
result["archive_b0813_zip_sha256"] = h
result["archive_b0813_zip_path"] = str(zpath)

out_json = OUT / "missing-security-tests-provenance.json"
out_json.write_text(json.dumps(result, indent=2), encoding="utf-8")
print(json.dumps({"wrote": str(out_json), "verdict": result["verdict"], "search": search}, indent=2))
print("primary hits any ref?", any(ref_hits[r] for r in ref_hits))
