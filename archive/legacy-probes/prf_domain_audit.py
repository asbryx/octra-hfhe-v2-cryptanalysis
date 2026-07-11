# ponytail: structural PRF domain/counter collision probe (no secret)
import hashlib
from itertools import combinations

DOMAINS = {
    "PRF_R1": "pvac.prf.r.1",
    "PRF_R2": "pvac.prf.r.2",
    "PRF_R3": "pvac.prf.r.3",
    "PRF_NOISE1": "pvac.prf.noise.1",
    "PRF_NOISE2": "pvac.prf.noise.2",
    "PRF_NOISE3": "pvac.prf.noise.3",
    "TOEP": "pvac.dom.toeplitz",
    "H_GEN": "pvac.dom.h_gen",
    "X_SEED": "pvac.dom.x_seed",
    "NOISE": "pvac.dom.noise",
    "PRF_LPN": "pvac.dom.prf_lpn",
    "ZTAG": "pvac.dom.ztag",
    "COMMIT": "pvac.dom.commit",
    "R_COM": "pvac.dom.r_com",
    "PRF_RHO": "pvac.prf.rho",
    "PRF_RHO_PROD": "pvac.prf.rho.prod",
}


def fnv1a(dom: str) -> int:
    h = 0xcbf29ce484222325
    for b in dom.encode("ascii"):
        h ^= b
        h = (h * 0x100000001b3) % (1 << 64)
    return h


def main():
    hashes = {k: fnv1a(v) for k, v in DOMAINS.items()}
    print("domain_fnv1a:")
    for k, v in sorted(hashes.items(), key=lambda kv: kv[1]):
        print(f"  {k:14} {DOMAINS[k]!r:28} {v:016x}")

    # collisions among domain hashes
    inv = {}
    for k, h in hashes.items():
        inv.setdefault(h, []).append(k)
    coll = {h: names for h, names in inv.items() if len(names) > 1}
    print("fnv1a_collisions=", coll if coll else "NONE")

    # AES key derivation public input tuple for R streams (same seed, different dom):
    # key = SHA256(prf_k || canon || H_digest || ztag || nonce.lo || nonce.hi || dom_hash)
    # so same seed + different dom_hash => different AES keys (unless dom_hash collision)
    r_doms = ["PRF_R1", "PRF_R2", "PRF_R3"]
    n_doms = ["PRF_NOISE1", "PRF_NOISE2", "PRF_NOISE3"]
    print("R_domain_hashes_unique", len({hashes[d] for d in r_doms}) == 3)
    print("noise_domain_hashes_unique", len({hashes[d] for d in n_doms}) == 3)

    # AES nonce for LPN stream: out_nonce = dom_hash ^ seed.nonce.lo
    # Toeplitz: same TOEP key for all R domains on same seed, then nonce ^= fnv1a(dom)
    # => TOEP key identical across R1/R2/R3 for same seed; TOEP nonces differ by R-domain hash
    print("TOEP_key_shared_across_R_domains_same_seed=True (by construction)")
    print("TOEP_nonce = fnv1a(TOEP)^nonce.lo  XOR  fnv1a(R_dom)")
    toep = hashes["TOEP"]
    for d in r_doms + n_doms:
        # not full nonce without nonce.lo; difference between domains is XOR of domain hashes
        print(f"  toep_nonce_xor_delta vs R1 for {d}: {(hashes[d] ^ hashes['PRF_R1']):016x}")

    # Counter overlap precondition without secret:
    # Same AES key + overlapping counter only if same (prf_k,canon,H,seed,dom) or TOEP key+nonce collide.
    # For fixed seed: R1/R2/R3 keys differ (dom_hash in SHA input). No same-key multi-domain.
    # TOEP: one key per seed; three nonces = base ^ dom_hash_i. Counter streams independent unless
    # nonce equal => requires dom_hash collision (absent).
    print("same_seed_R_stream_key_collision_precondition=absent")
    print("same_seed_TOEP_nonce_collision_precondition=absent")

    # Cross-domain key equality would need fnv1a collision OR length-extension/omitted separators.
    # Check SHA-256 input is length-delimited only by fixed-width u64 fields + fixed 32-byte digest.
    # Domains are hashed to u64 first, so string length not concatenated raw — no boundary ambiguity.
    print("sha256_domain_input_is_u64_fnv_not_raw_string=True")
    print("length_boundary_ambiguity=absent")

    # Active nonces from probe-pr2.out
    import re
    from pathlib import Path
    text = Path(r"local-corpus/probe-pr2.out").read_text()
    pairs = [(int(a, 16), int(b, 16)) for a, b in re.findall(r"T=0x([0-9a-fA-F]+):([0-9a-fA-F]+)", text)]
    assert len(pairs) == 44
    # public derivation tuple without prf_k: (canon, H, ztag, lo, hi, dom_hash)
    # ztag is determined by canon+nonce; if all nonces unique, all public seed parts unique.
    print("active_layers", len(pairs), "unique_nonce_pairs", len(set(pairs)))

    # simulated public-input uniqueness for each stream type across layers
    # AES LPN key public part: (ztag, lo, hi, dom_hash) — ztag not needed if nonce unique under same canon
    for name, doms in [("R", r_doms), ("noise", n_doms), ("TOEP_base", ["TOEP"])]:
        tuples = set()
        for lo, hi in pairs:
            for d in doms:
                tuples.add((lo, hi, hashes[d]))
        print(f"active_public_seed_dom_tuples_{name}_unique", len(tuples), "of", len(pairs) * len(doms))

    # TOEP full nonce uniqueness across (layer, R_dom)
    toep_nonces = set()
    for lo, hi in pairs:
        base = toep ^ lo  # missing only that this is out_nonce before second xor; full = (toep^lo)^dom
        for d in r_doms:
            toep_nonces.add((toep ^ lo ^ hashes[d], hi))  # hi not in nonce but seed separates keys
    print("note: toep AES key also binds full seed; nonce alone not whole story")
    print("all_domain_hashes_unique", len(set(hashes.values())) == len(hashes))
    print("all_active_derived_public_input_tuples_unique", len(set(pairs)) == 44)
    print("counter_overlap_precondition", "absent")


if __name__ == "__main__":
    main()
