#!/usr/bin/env python3
"""Source-level regression check for Circle read/HFHE authorization guards."""

import argparse
from pathlib import Path


CHECKS = {
    "node_runtime/circle_auth.ml": [
        'op ^ "|" ^ circle_id ^ "|" ^ addr',
        "verify_address_pubkey auth.addr auth.pub_b64",
        "Mirage_crypto_ec.Ed25519.verify ~key:pk_ed ~msg sig_raw",
        "match check_gate info addr gate",
    ],
    "node_runtime/circle_read_rpc.ml": [
        "~gate:(Circle_auth.Storage_owner_if include_storage)",
        '~op:"octra_circle_view"',
        "~subject:(Circle_view.view_subject",
    ],
    "lib/core/circle_policy/circle_hfhe_policy.ml": [
        "encrypt_mode = Owner_only;",
        "decrypt_mode = Owner_only;",
        "cipher_serde_mode = Owner_only;",
        "pubkey_serde_mode = Owner_only;",
        "| Owner_only -> caller = owner",
    ],
    "circle_runtime/circle_exec.ml": [
        "Some _ when not key_ops_allowed ->",
        "ctx.allow_fhe_capability ContractVM.Fhe_decrypt_cap",
        "Pvac_ffi.serialize_seckey sk",
    ],
}


def check(root: Path) -> dict:
    missing = []
    for relative, needles in CHECKS.items():
        text = (root / relative).read_text(encoding="utf-8")
        missing.extend(f"{relative}: {needle}" for needle in needles if needle not in text)
    return {
        "root": str(root),
        "checks": sum(map(len, CHECKS.values())),
        "missing": missing,
        "verdict": "guards present" if not missing else "guard regression",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("lite_node", type=Path)
    args = parser.parse_args()
    result = check(args.lite_node)
    print(f"checks={result['checks']} missing={len(result['missing'])}")
    for item in result["missing"]:
        print(item)
    assert not result["missing"], result["verdict"]


if __name__ == "__main__":
    main()
