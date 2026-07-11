#!/usr/bin/env python3
"""RP-07: lightweight public anchor comparison."""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

OUT = Path(r"archive/legacy-probes/rp-07/rp07_anchor.json")

# From plan + prior QP-07
ANCHORS = {
    "challenge_HEAD": "0d08e9622921e5930175a660df0061a65548972f",
    "challenge_forks": 26,
    "challenge_PRs_all": 4,  # after QP-07
    "PVAC_HEAD": "071b0e909c119de815e284b347c4bd979cb59ef3",
    "PVAC_open_PRs": 2,
    "PVAC_open_issues": [501, 502, 503],
}


def gh_jq(path, jq):
    return subprocess.check_output(
        ["gh", "api", path, "--jq", jq], text=True, timeout=60
    ).strip()


def main():
    ch_head = gh_jq("repos/octra-labs/hfhe-challenge/commits/main", ".sha")
    ch_forks = int(gh_jq("repos/octra-labs/hfhe-challenge", ".forks_count"))
    ch_prs = int(
        subprocess.check_output(
            [
                "gh",
                "api",
                "repos/octra-labs/hfhe-challenge/pulls?state=all&per_page=100",
                "--jq",
                "length",
            ],
            text=True,
            timeout=60,
        ).strip()
    )
    pvac_head = gh_jq("repos/octra-labs/pvac_hfhe_cpp/commits/main", ".sha")
    pvac_forks = int(gh_jq("repos/octra-labs/pvac_hfhe_cpp", ".forks_count"))
    pvac_prs = json.loads(
        subprocess.check_output(
            [
                "gh",
                "api",
                "repos/octra-labs/pvac_hfhe_cpp/pulls?state=open&per_page=20",
                "--jq",
                "[.[]|.number]",
            ],
            text=True,
            timeout=60,
        )
    )
    pvac_issues = json.loads(
        subprocess.check_output(
            [
                "gh",
                "api",
                "repos/octra-labs/pvac_hfhe_cpp/issues?state=open&per_page=20",
                "--jq",
                "[.[]|select(.pull_request|not)|.number]",
            ],
            text=True,
            timeout=60,
        )
    )

    # Kubo watcher: search recent issues/PRs mentioning audit — light only
    kubo_hits = []
    try:
        # search github for Kubo100x related to octra hfhe since challenge
        out = subprocess.check_output(
            [
                "gh",
                "api",
                "search/issues?q=Kubo100x+hfhe+OR+Kubo+octra+hfhe&per_page=5",
                "--jq",
                "[.items[]|{title,html_url,created_at}]",
            ],
            text=True,
            timeout=60,
        )
        kubo_hits = json.loads(out)
    except Exception as e:
        kubo_hits = [{"error": str(e)}]

    observed = {
        "challenge_HEAD": ch_head,
        "challenge_forks": ch_forks,
        "challenge_PRs_all": ch_prs,
        "PVAC_HEAD": pvac_head,
        "PVAC_forks": pvac_forks,
        "PVAC_open_PRs": pvac_prs,
        "PVAC_open_issues": pvac_issues,
    }
    changes = []
    if ch_head != ANCHORS["challenge_HEAD"]:
        changes.append("challenge_HEAD")
    if ch_forks != ANCHORS["challenge_forks"]:
        changes.append("challenge_forks")
    if ch_prs != ANCHORS["challenge_PRs_all"]:
        changes.append("challenge_PRs")
    if pvac_head != ANCHORS["PVAC_HEAD"]:
        changes.append("PVAC_HEAD")
    if len(pvac_prs) != ANCHORS["PVAC_open_PRs"]:
        changes.append("PVAC_open_PRs")
    for n in ANCHORS["PVAC_open_issues"]:
        if n not in pvac_issues:
            changes.append(f"missing_issue_{n}")

    report = {
        "probe": "RP-07",
        "date_utc": datetime.now(timezone.utc).isoformat(),
        "anchors": ANCHORS,
        "observed": observed,
        "changes": changes,
        "kubo_watcher_hits": kubo_hits,
        "full_scan_run": bool(changes),
        "verdict": "CLOSED" if not changes else "DELTA",
        "note": (
            "No anchor change since QP-07 baseline; skip full fork rescan."
            if not changes
            else "Anchor changed — expand scan."
        ),
    }
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
