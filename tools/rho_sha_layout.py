#!/usr/bin/env python3
"""Audit the exact SHA-256 layout used by active BASE-layer rho values."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

TAG = b"pvac.prf.rho"
SCALAR_ORDER = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED


def padded(message: bytes) -> bytes:
    out = bytearray(message)
    out.append(0x80)
    out.extend(b"\0" * ((56 - len(out)) % 64))
    out.extend((len(message) * 8).to_bytes(8, "big"))
    return bytes(out)


def rho_digest(key: bytes, nonce_lo: int, nonce_hi: int, slot: int = 0) -> bytes:
    message = TAG + key + nonce_lo.to_bytes(8, "little") + nonce_hi.to_bytes(8, "little") + slot.to_bytes(8, "little")
    return hashlib.sha256(message).digest()


def common_prefix(values: list[bytes]) -> int:
    if not values:
        return 0
    return next((i for i, column in enumerate(zip(*values)) if len(set(column)) != 1), min(map(len, values)))


def audit(equation_map: Path) -> dict:
    data = json.loads(equation_map.read_text(encoding="utf-8"))
    layers = [layer for obj in data["objects"] for layer in obj["layers"]]
    if len(layers) != 44:
        raise ValueError(f"expected 44 layers, got {len(layers)}")

    key = bytes(range(32))
    messages = [
        TAG
        + key
        + int(layer["nonce_lo_hex"], 16).to_bytes(8, "little")
        + int(layer["nonce_hi_hex"], 16).to_bytes(8, "little")
        + (0).to_bytes(8, "little")
        for layer in layers
    ]
    blocks = [padded(message) for message in messages]
    if any(len(message) != 68 for message in messages) or any(len(value) != 128 for value in blocks):
        raise AssertionError("unexpected rho SHA geometry")

    digests = [hashlib.sha256(message).digest() for message in messages]
    scalars = [int.from_bytes(digest, "little") % SCALAR_ORDER for digest in digests]
    first_message = messages[0]
    flipped_digest = flipped_scalar = 0
    for bit in range(256):
        candidate = bytearray(key)
        candidate[bit // 8] ^= 1 << (bit % 8)
        digest = rho_digest(bytes(candidate), int(layers[0]["nonce_lo_hex"], 16), int(layers[0]["nonce_hi_hex"], 16))
        flipped_digest += digest != digests[0]
        flipped_scalar += int.from_bytes(digest, "little") % SCALAR_ORDER != scalars[0]

    quotient, remainder = divmod(1 << 256, SCALAR_ORDER)
    result = {
        "input": {
            "equation_map": equation_map.as_posix(),
            "layers": len(layers),
            "unique_nonces": len({(layer["nonce_lo_hex"], layer["nonce_hi_hex"]) for layer in layers}),
            "slot": 0,
        },
        "message_layout": {
            "tag_bytes": len(TAG),
            "key_bytes": 32,
            "nonce_bytes": 16,
            "slot_bytes": 8,
            "message_bytes": len(first_message),
            "sha_blocks": len(blocks[0]) // 64,
            "common_prefix_bytes": common_prefix(messages),
            "shared_complete_prefix_blocks": common_prefix(messages) // 64,
            "unique_block0": len({value[:64] for value in blocks}),
            "unique_block1": len({value[64:] for value in blocks}),
            "block1_hex": blocks[0][64:].hex(),
        },
        "dummy_key_checks": {
            "key_hex": key.hex(),
            "unique_raw_digests": len(set(digests)),
            "unique_reduced_scalars": len(set(scalars)),
            "key_bits_affecting_raw_digest": flipped_digest,
            "key_bits_affecting_reduced_scalar": flipped_scalar,
        },
        "scalar_reduction": {
            "order_bit_length": SCALAR_ORDER.bit_length(),
            "log2_order": math.log2(SCALAR_ORDER),
            "raw_digest_bits": 256,
            "quotient_floor_2^256_over_L": quotient,
            "residue_classes_with_one_extra_preimage": remainder,
            "preimages_per_scalar_min": quotient,
            "preimages_per_scalar_max": quotient + 1,
        },
        "cryptanalytic_gates": {
            "length_extension_recovers_key": False,
            "shared_full_sha_midstate_across_nonces": False,
            "scalar_reduction_is_keyspace_search_reduction": False,
            "note": "The secret key enters block 0 before each unique nonce. Reduction loses about four output bits but does not provide a way to enumerate matching 256-bit keys.",
        },
    }

    assert result["input"]["unique_nonces"] == 44
    assert result["message_layout"]["common_prefix_bytes"] == len(TAG) + 32
    assert result["message_layout"]["shared_complete_prefix_blocks"] == 0
    assert result["message_layout"]["unique_block0"] == 44
    assert result["message_layout"]["unique_block1"] == 1
    assert flipped_digest == flipped_scalar == 256
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("equation_map", type=Path)
    parser.add_argument("--out", type=Path, default=Path(__file__).with_name("rho_sha_layout.json"))
    args = parser.parse_args()
    result = audit(args.equation_map)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
