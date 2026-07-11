> **Historical snapshot.** This file preserves an earlier experiment record. Some commit labels, checkout hashes, local paths, and broad verdict wording were later corrected or narrowed. Use `../STATUS.md` and `../research/final-exhaustion.md` as authoritative.

# Octra HFHE Challenge v2 — Detailed Results

## Phase 0 lock

- challenge `0d08e962…` / pvac `071b0e9…`
- four public hashes match; magic BTY02; 22 objects

---

# CF-T1..T8 (prior continuation)

## CF-T1 — pk.bin compress boundary
**CLOSED.** unread=0, repack_exact=1, trunc/mut end fails.
raw SHA `67e8538a…ce28`. Probes: `hfhe_unpack_boundary.rs`, pk-compress-probe.

## CF-T2 — unique forks
**CLOSED.** nxpath/Eienel tools only; pk/ct = active; no sk/plaintext blobs.

## CF-T3 — toy graph best-case
**CLOSED.** N_sig8==N_all; residual still needs R. Scripts: `pvac-v2-r-prf-audit.py`, `toy_graph_bestcase.py`.

## CF-T4 — wrapped-PC verifier
**CLOSED.** delta zero_rate≈0; rho blinds D(v). Script: `wrapped_pc_delta_probe.py`.

## CF-T5a — rho uniqueness
**CLOSED.** 44/44 unique nonces. `seeds_active.txt`.

## CF-T5b — PRF domain/counter
**CLOSED.** 16 domain hashes unique; counter_overlap=absent. `prf_domain_audit.py`.

## CF-T5c — cross-epoch reuse
**CLOSED.** active ∩ e464 ∩ 08bf nonces = 0. `seeds_*.txt`.

## CF-T5d — CI/release/search
**CLOSED.** no secret assets; generator keygen+enc_text only.

## CF-T6 — wire structure
**CLOSED.**
```
base=44 non_base=0 edges=1829 unique_pc=44
c0_nonzero=0 trailing=0
```
`active_edge.txt`

## CF-T7 — R_com oracle
**CLOSED.** cdc6a52 removed R from hash; not on v3 wire.

## CF-T8 — wallet-gen/webcli/fsck
**CLOSED.** no active-bound hits.

---

# NP-01..07 (NEXT_PLAN_AFTER_CF_T8)

## NP-01 — public delta
**CLOSED.**
```
old_forks=22 current=26
new: akidry, ifeoluwaaj, JH-321, k3llgh
unique_commits=0  all HEAD=0d08e962…
pk/ct all match active
PR#3 analysis-only
```
`public-delta-20260710.json`

## NP-02 — issue #503 ristretto non-canonical
**CLOSED.**
```
issue_repro noncanon_accepted=1 same_point=1
active G+H+44 PC: hi_bit=0 decode_fail=0 reenc_mismatch=0
```
Not an opening of fixed secret.ct. `probes/pc_canon_check.cpp`

## NP-03 — finite wallet candidates
**CLOSED.**
```
candidate_seeds=99  paths≈4  tests≈396  hits=0
```
Corrected ct hash `5da7…` (not eienel typo `5da3…`).
`probes/np03_wallet_candidates.py`

## NP-04 — payload templates
**CLOSED.**
| template | len | fits 301–315 |
|----------|-----|--------------|
| wallet-gen txt export | 637–656 | no |
| bounty3 mnemonic+number | ~90–110 | no |
| short json/key dumps | <300 | usually no |
| free-form + pad | can | yes but full entropy remains |

`payload-template-matrix.csv` (retained as `archive/payload-template-matrix.csv`)

## NP-05 — wallet provenance
**CLOSED.** wallet-gen uses `crypto.randomBytes`; stock export ≠ active length; no public demo seed path.

## NP-07 — funding / timeline
**CLOSED.**
```json
{
  "tx": "ad1af0cf96a12105bb112b0f3f7275e8fbd713e2f6966d886f5ec2c04e514898",
  "from": "oct7xCozDD9JEsbeVpo5C7HXp2BJbKqfmNUHmDDCCTtWcGb",
  "amount": "500000",
  "message": null,
  "op_type": "standard",
  "timestamp_utc": "2026-07-09T20:52:07.265424+00:00",
  "has_public_key": false,
  "account_nonce": 0
}
```
Order: e464 publish 20:33Z → fund 20:52Z → active 88a72b7 21:08Z.
`probes/funding-tx.json`  RPC: `https://octra.network/rpc`

---

# Not run

- **NP-06** Toeplitz effective window + LPN/PRF influence
- **NP-08** active H GF(2) rank (deprioritized)

---

# SOLVED? No

None of: full plaintext recovery, matching sk decrypt, public-only reproducible procedure.
