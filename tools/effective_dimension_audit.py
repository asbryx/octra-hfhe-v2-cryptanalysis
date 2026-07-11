#!/usr/bin/env python3
"""Audit PRF-key input diffusion and public counter geometry for the live R1 corpus."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from Crypto.Cipher import AES

HERE = Path(__file__).resolve().parent
META = HERE.parent / "results" / "lpn_corpus_validation.json"
OUT = HERE.parent / "results" / "effective_dimension_audit.json"
MASK64 = (1 << 64) - 1
CANON_TAG = 531565633433868593
H_DIGEST = bytes.fromhex("601435f4977dd2a0c396bd96c7947fb884b602a52b6d7e0660b3fce3508497f5")
DOMAINS = ("pvac.prf.r.1", "pvac.prf.r.2", "pvac.prf.r.3")
TOEPLITZ = "pvac.dom.toeplitz"


def fnv1a(domain: str) -> int:
    value = 0xCBF29CE484222325
    for byte in domain.encode("ascii"):
        value = ((value ^ byte) * 0x100000001B3) & MASK64
    return value


def derive(words: list[int], seed: tuple[int, int, int], domain: str) -> tuple[bytes, int]:
    digest = hashlib.sha256()
    for word in words:
        digest.update(struct.pack("<Q", word))
    digest.update(struct.pack("<Q", CANON_TAG))
    digest.update(H_DIGEST)
    digest.update(struct.pack("<QQQ", *seed))
    domain_hash = fnv1a(domain)
    digest.update(struct.pack("<Q", domain_hash))
    return digest.digest(), domain_hash ^ seed[1]


def first_block(key: bytes, nonce: int) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(struct.pack("<QQ", nonce, 0))


def hamming(left: bytes, right: bytes) -> int:
    return sum((a ^ b).bit_count() for a, b in zip(left, right))


def overlap(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return max(left[0], right[0]) <= min(left[1], right[1])


def main() -> None:
    corpus = json.loads(META.read_text(encoding="utf-8"))
    seeds = [
        (
            entry["header"]["seed_ztag"],
            int(entry["header"]["nonce_lo_hex"], 16),
            int(entry["header"]["nonce_hi_hex"], 16),
        )
        for entry in corpus["files"]
    ]
    assert len(seeds) == len(set(seeds)) == 44

    baseline = [0, 0, 0, 0]
    base_key, base_nonce = derive(baseline, seeds[0], DOMAINS[0])
    base_block = first_block(base_key, base_nonce)
    key_distances, block_distances = [], []
    for bit in range(256):
        words = baseline.copy()
        words[bit // 64] ^= 1 << (bit % 64)
        key, nonce = derive(words, seeds[0], DOMAINS[0])
        assert nonce == base_nonce
        key_distances.append(hamming(base_key, key))
        block_distances.append(hamming(base_block, first_block(key, nonce)))

    overlaps = []
    for index, seed in enumerate(seeds):
        _, base = derive(baseline, seed, TOEPLITZ)
        ranges = {
            domain: (base ^ fnv1a(domain), (base ^ fnv1a(domain)) + 128)
            for domain in DOMAINS
        }
        for offset, left in enumerate(DOMAINS):
            for right in DOMAINS[offset + 1 :]:
                if overlap(ranges[left], ranges[right]):
                    overlaps.append([index, left, right])

    starts = [derive(baseline, seed, DOMAINS[0])[1] for seed in seeds]
    result = {
        "input_bits_tested": 256,
        "derived_key_changed": sum(distance > 0 for distance in key_distances),
        "first_block_changed": sum(distance > 0 for distance in block_distances),
        "derived_key_hamming": {
            "min": min(key_distances),
            "max": max(key_distances),
            "mean": sum(key_distances) / len(key_distances),
        },
        "first_block_hamming": {
            "min": min(block_distances),
            "max": max(block_distances),
            "mean": sum(block_distances) / len(block_distances),
        },
        "unique_r1_counter_starts": len(set(starts)),
        "toeplitz_range_overlaps_within_seed": overlaps,
    }
    assert result["derived_key_changed"] == 256
    assert result["first_block_changed"] == 256
    assert result["unique_r1_counter_starts"] == 44
    assert not overlaps
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
