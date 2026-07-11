#!/usr/bin/env python3
"""QP-07: one-shot public anchor comparison; full scan only if changed."""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

OUT = Path(r"archive/legacy-probes/qp-07/qp07_delta.json")

ANCHORS = {
    "challenge_HEAD": "0d08e9622921e5930175a660df0061a65548972f",
    "challenge_forks": 26,
    "challenge_PRs": 3,
    "PVAC_pinned": "071b0e909c119de815e284b347c4bd979cb59ef3",
    "PVAC_open_issues_include": [501, 502, 503],
    "PVAC_open_PRs": 2,
}


def gh_json(args: list[str]):
    out = subprocess.check_output(["gh", *args], text=True, timeout=60)
    return json.loads(out)


def main() -> None:
    ch_repo = gh_json(
        [
            "api",
            "repos/octra-labs/hfhe-challenge",
            "--jq",
            "{forks:.forks_count, open_issues:.open_issues_count, pushed:.pushed_at, default:.default_branch}",
        ]
    )
    # HEAD sha
    ch_head = subprocess.check_output(
        ["gh", "api", "repos/octra-labs/hfhe-challenge/commits/main", "--jq", ".sha"],
        text=True,
        timeout=60,
    ).strip()
    ch_prs = gh_json(
        [
            "api",
            "repos/octra-labs/hfhe-challenge/pulls?state=all&per_page=100",
            "--jq",
            "length",
        ]
    )
    # if length jq not work:
    if not isinstance(ch_prs, int):
        ch_prs = len(
            gh_json(
                [
                    "api",
                    "repos/octra-labs/hfhe-challenge/pulls?state=all&per_page=100",
                ]
            )
        )

    pvac_repo = gh_json(
        [
            "api",
            "repos/octra-labs/pvac_hfhe_cpp",
            "--jq",
            "{forks:.forks_count, open_issues:.open_issues_count, pushed:.pushed_at}",
        ]
    )
    pvac_head = subprocess.check_output(
        ["gh", "api", "repos/octra-labs/pvac_hfhe_cpp/commits/main", "--jq", ".sha"],
        text=True,
        timeout=60,
    ).strip()
    pvac_open_prs = gh_json(
        [
            "api",
            "repos/octra-labs/pvac_hfhe_cpp/pulls?state=open&per_page=20",
            "--jq",
            "[.[]|.number]",
        ]
    )
    pvac_open_issues = gh_json(
        [
            "api",
            "repos/octra-labs/pvac_hfhe_cpp/issues?state=open&per_page=20",
            "--jq",
            "[.[]|select(.pull_request|not)|.number]",
        ]
    )

    observed = {
        "challenge_HEAD": ch_head,
        "challenge_forks": ch_repo["forks"],
        "challenge_PRs_all_count": ch_prs,
        "challenge_pushed_at": ch_repo["pushed"],
        "PVAC_HEAD": pvac_head,
        "PVAC_forks": pvac_repo["forks"],
        "PVAC_open_issues": pvac_open_issues,
        "PVAC_open_PRs": pvac_open_prs,
        "PVAC_open_PR_count": len(pvac_open_prs),
        "PVAC_pushed_at": pvac_repo["pushed"],
    }

    changes = []
    if observed["challenge_HEAD"] != ANCHORS["challenge_HEAD"]:
        changes.append("challenge_HEAD")
    if observed["challenge_forks"] != ANCHORS["challenge_forks"]:
        changes.append("challenge_forks")
    # PR count: plan said 3 in latest inventory
    if observed["challenge_PRs_all_count"] != ANCHORS["challenge_PRs"]:
        changes.append("challenge_PRs")
    if observed["PVAC_HEAD"] != ANCHORS["PVAC_pinned"]:
        # HEAD may advance beyond pin; only flag if different AND new unique content needed
        changes.append("PVAC_HEAD_vs_pin")
    if observed["PVAC_open_PR_count"] != ANCHORS["PVAC_open_PRs"]:
        changes.append("PVAC_open_PRs")
    for n in ANCHORS["PVAC_open_issues_include"]:
        if n not in observed["PVAC_open_issues"]:
            changes.append(f"missing_issue_{n}")

    # Plan: run delta scan only if one value changed.
    # PVAC_HEAD advancing beyond pin without pin change is expected; treat pin as lock not live HEAD.
    meaningful = [c for c in changes if c != "PVAC_HEAD_vs_pin"]
    # If only PVAC head moved but pin still what we audit, not a challenge delta.
    run_full_scan = bool(meaningful)

    report = {
        "probe": "QP-07",
        "date_utc": datetime.now(timezone.utc).isoformat(),
        "anchors": ANCHORS,
        "observed": observed,
        "raw_changes": changes,
        "meaningful_changes": meaningful,
        "full_delta_scan_run": run_full_scan,
        "verdict": "NO_DELTA" if not meaningful else "DELTA_DETECTED",
        "note": (
            "No meaningful public anchor change; skip full fork/PR rescan."
            if not meaningful
            else "Anchor changed — full public delta scan warranted."
        ),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
