> **Historical snapshot.** This file preserves an earlier experiment record. Some commit labels, checkout hashes, local paths, and broad verdict wording were later corrected or narrowed. Use `../STATUS.md` and `../research/final-exhaustion.md` as authoritative.

# Executor Results After NP-07 — QP-01..QP-07

**Date:** 2026-07-11
**Agent role:** execution only (no new plan; no edits to STATUS/RESULTS/audit-log/NEXT_PLAN)
**Status of challenge:** still **NOT SOLVED**

## Target lock (verified before work)

| Item | Expected | Observed |
|------|----------|----------|
| Challenge HEAD | `0d08e9622921e5930175a660df0061a65548972f` | match (`upstream/hfhe-challenge`) |
| PVAC HEAD | `071b0e909c119de815e284b347c4bd979cb59ef3` | match (`upstream/pvac_hfhe_cpp`) |
| secret.ct | `5da7f827…23fbab` | match |
| pk.bin | `1e788edf…5e9410` | match |
| pk.raw | `67e8538a…c2ce28` | match (`local-corpus/pk.raw`) |
| params.json | `24bf1290…397d80` | match |
| manifest.json | `0cbda19f…9cc18c` | match |
| canon_tag | `531565633433868593` | match |
| H_digest | `601435f4…8497f5` | match |

Lock OK — execution proceeded.

## Summary table

| ID | Verdict | One-line reason |
|----|---------|-----------------|
| QP-01 | **CLOSED** | Missing security-test `.cpp` sources never exist as public blobs (Makefile stubs only) |
| QP-02 | **PROVEN → continue** | Toeplitz/PRF core full == 127-bit truncated on active params |
| QP-03 | **CLOSED** | Combined active-seed rank hits 4096 by group 33; zero secret-bit influence = 0 across 8 keys |
| QP-04 | **SKIPPED** | Plan gate: only if QP-03 promotes; QP-03 closed |
| QP-05 | **CLOSED** | Active public H rank = 8192 (full); left kernel dim = 0 |
| QP-06 | **CLOSED** | All deterministic producer fields match pinned `071b0e9` / active artifacts |
| QP-07 | **CLOSED (trivial delta)** | challenge PR count 3→4 (PR#4 analysis-only); pk/ct still active hashes |

---

## QP-01 — Recover missing security-test sources

### Hypothesis
`tests/poc_pc_forge_soundness.cpp`, `tests/forge_decrypt_payload.cpp`, `tests/test_ristretto255.cpp` (Makefile targets since `b0813def`) exist somewhere public and may open BASE PC / decrypt without sk.

### Exact inputs and hashes
- Pinned PVAC: `071b0e909c119de815e284b347c4bd979cb59ef3`
- Introduction commit: `b0813def89db6b4f82dd2cea39f1cfcdc670f9d2` (Makefile only)
- codeload zip of `b0813def`: 17699280 bytes, SHA-256 `c0c223a20e0978e170120abf6a8991e895c478bfcd21b88299fb7215a3c48dbe` (cached `/tmp/pvac-b0813.zip` probe note)

### Smallest reproducible probe
```bash
# local history
cd upstream/pvac_hfhe_cpp
git rev-list --all | while read c; do git ls-tree -r --name-only $c | rg 'poc_pc_forge|forge_decrypt|test_ristretto255'; done
# PR refs
git fetch origin refs/pull/490/head refs/pull/499/head refs/pull/500/head
# raw 404s
curl -sS -o /dev/null -w "%{http_code}\n" \
  https://raw.githubusercontent.com/octra-labs/pvac_hfhe_cpp/main/tests/poc_pc_forge_soundness.cpp
# code search (gh)
gh search code "poc_pc_forge_soundness" --limit 20
```

### Evidence
- Makefile references **38** test `.cpp` paths; **10** missing on disk including the three targets + 7 other security/proof stubs.
- Full local `rev-list --all` tree scan: **0** hits for target paths.
- PR heads 490/499/500: no target sources.
- codeload archive of `b0813def`: 34 test cpp files, none of the three names.
- GitHub code search: only **Makefile** hits in `octra-labs/pvac_hfhe_cpp`.
- Public web code search `result_count=0` for source filename.
- GH Archive sample `2026-07-07` hour 9: 164515 lines, **0** filename hits.
- Author fork `lambda0xE/pvac_hfhe_cpp` HEAD `087ff245…`: 404 for all three.
- **62** PVAC forks enumerated; **20** unique HEADs; raw checks on divergent HEADs all 404; local trees for reachable unique commits: no targets.

### Independent check
Broader missing-Makefile set (10 files) also absent from every reachable tree → pattern is “aspirational Makefile targets never committed,” not a force-pushed single file.

### Verdict: **CLOSED**
No source recovered → cannot bind any forge/decrypt PoC to fixed active `secret.ct`.

### Deliverable
- `../tools/qp-01\missing-security-tests-provenance.json`
  SHA-256: `d75c72f9e8ff3a2fdf0e7ff07aeec1ccc93656d980fe8c1d47984db8274fd94c`
- `../tools/qp-01\fork-heads.tsv`
  SHA-256: `3d32af5628a818597027d71691450f7f3e414e74e1e0168268d8813154ad4182`

### Next dependency
None from QP-01. Proceed QP-02.

---

## QP-02 — Toeplitz effective window / PRF truncation

### Hypothesis
`toep_127` output depends only on input bits `0..126` of both `top` and `ybits`; therefore full `prf_R_core` equals a 127-row / 127-bit-truncated variant under active parameters.

### Exact inputs
- Official headers: `include/pvac/crypto/toeplitz.hpp`, `include/pvac/crypto/lpn.hpp`
- Active: `lpn_t=16384`, `lpn_n=4096`, canon/H_digest from STATUS

### Smallest reproducible commands
```bash
cd "archive/legacy-probes/qp-02"
clang++ -std=c++17 -O2 -mpclmul -msse2 -I"upstream/pvac_hfhe_cpp/include" \
  qp02_toep_window.cpp -o qp02_toep_window.exe
./qp02_toep_window.exe

clang++ -std=c++17 -O2 -D_CRT_SECURE_NO_WARNINGS -maes -msse2 -mpclmul \
  -I"upstream/pvac_hfhe_cpp/include" qp02_prf_trunc.cpp -o qp02_prf_trunc.exe
./qp02_prf_trunc.exe
```

### Raw observed output
```text
effective_top_bits=127
effective_y_bits=127
full_vs_truncated_match_count=256/256
scalar_vs_pclmul_match_count=256/256
negctrl_flip_bit127_changes=0/256
negctrl_flip_bit0_changes=256/256
verdict=TRUNCATION_EQUIVALENCE_PROVEN

seeds=16 domains_per_seed=6 (3R+3noise)
full_vs_mask127_match=96/96
full_vs_earlystop127_match=96/96
full_prf_core_eq_truncated_127_prf_core=YES
verdict=PRF_TRUNCATION_EQUIVALENCE_PROVEN
```

### Independent check
Negative controls: flipping y-bit 127 never changes output; flipping y-bit 0 always does (256/256). Scalar == PCLMUL. Mask-after-full-AES and early-stop-after-127-rows both match full `prf_R_core` (early-stop matches because unused AES stream after row 126 is never consumed by Toeplitz).

### Verdict: **PROVEN** (not a solve)
Meaning limit (plan §4): reduces per-domain LPN transcript **16384 → 127 rows**, not the 4096-bit secret dimension, and not the 256-bit `prf_k`.

### Artifacts
| Path | SHA-256 |
|------|---------|
| `probes/qp-02/qp02_toep_window.cpp` | `271072b6c6d27d524b9624dd978aa08039efc5c3bcc84a2d8d77790165ca7126` |
| `probes/qp-02/qp02_toep_window.out` | `8a3a57a7e16583a686db8b97eb43fde1d33a845ee800fafb67cbba123a0eda79` |
| `probes/qp-02/qp02_prf_trunc.cpp` | `71cd2217e475d80d5721ecbadd6d232bd150165800f0204bfd74ef72319bbd4f` |
| `probes/qp-02/qp02_prf_trunc.out` | `6e9b966c4b78f3f98f53fb434cc083837fd79b179af87cb6090b98c7a3ad083b` |
| `probes/qp-02/qp02_summary.json` | `2f83c2196e459f8275ca5cf76f631e192f0bbd25057b402a324e3751d233e782` |

### Next dependency
QP-03 (gate opened by QP-02 success).

---

## QP-03 — Active-seed LPN rank / influence

### Hypothesis
Even with 127-row truncation, the 44 active BASE seeds × 3 R-domains may leave a large secret kernel (rank ≪ 4096 or many zero-influence bits).

### Exact inputs
- 44 active seeds from `probes/seeds_active.txt` (ztag/lo/hi)
- Domains: `pvac.prf.r.1/2/3`
- Rows/group: 127; columns: 4096
- Dummy `prf_k` set: 8 deterministic 256-bit keys
- Active canon + H_digest in key derivation

### Smallest reproducible command
```bash
cd "archive/legacy-probes/qp-03"
python3 -u qp03_lpn_rank.py
# or resume phase C from partial JSON
```

### Evidence
**Phase A (dummy key 0):**
- Rank after group g: ≈ 127·g until saturation
- `groups_to_full_rank = 33` (seed index 10, domain R3)
- `final_rank = 4096` over all 132 groups

**Phase B:**
- `lpn_bits_with_zero_row_influence = 0`
- `lpn_bits_with_zero_output_influence = 0` (linear LPN: influence ≡ column support; errors independent of s)
- `support_bits = 4096`

**Phase C (8 keys):** every key
`combined_rank=4096`, `groups_to_full_rank=33`, `zero_row_influence_bits=0`.

### Independent check
Rank grows by exactly +127 per new seed/domain group until near full rank (trace in JSON), consistent with random AES rows of width 4096. Full rank at group 33 is ~11 seeds × 3 domains ≈ 4191 row budget > 4096.

### Verdict: **CLOSED** (no promote)
Does **not** meet promote conditions (rank far below 4096 / hundreds of inert secret bits / public projection independent of `prf_k`).
Toeplitz truncation is a **design/security-margin** finding only: rows still require full 256-bit `prf_k`, and no R-core output is public.

### Artifacts
| Path | SHA-256 |
|------|---------|
| `probes/qp-03/qp03_lpn_rank.py` | `a09a19308dd0973173b47beeb2bbbdd758d247deacfb575a03cb8c44a37ac2ca` |
| `probes/qp-03/qp03_rank_influence.json` | `7a16135e646bd6faf0e900ac64189c7ad8da8d5428aa178c2e6e284583056944` |

### Next dependency
QP-04 **not** run (plan gate).

---

## QP-04 — Same-key R/rho toy verifier

### Hypothesis
(N/A this session) Coupling rho and R through shared `prf_k` yields a public partial-key verifier.

### Decision: **SKIPPED**
Plan §6 / execution order: run only if QP-03 finds a meaningful reduction. QP-03 closed with full rank and zero inert bits.

### Artifact
- `probes/qp-04/qp04_skipped.json`
  SHA-256: `b0b5e964ec92f1d1bf5b3014cb9c8f5e110ca560c724e9ca033852515eb23fb8`

### Next dependency
None. Stop rule: no SAT/SMT/GPU solver.

---

## QP-05 — Active public-H rank (one pass)

### Hypothesis
8192×16384 public H is rank-deficient and a left-kernel projection correlates with decryption-relevant quantities (not only sigma).

### Exact inputs
- `local-corpus/pk.raw` SHA-256 `67e8538a…c2ce28`
- Dimensions m=8192, n=16384, h_col_wt=192

### Smallest reproducible command
```bash
cd "archive/legacy-probes/qp-05"
clang++ -std=c++17 -O3 qp05_h_rank.cpp -o qp05_h_rank.exe
./qp05_h_rank.exe "local-work/pk.raw"
```

### Raw output
```text
active_H_rank=8192
left_kernel_dimension=0
m_bits=8192 n_bits=16384 h_col_wt=192 B=337
canon_tag=531565633433868593
rank_seconds=9.676
verdict=FULL_RANK_CLOSED
```

### Independent check
Parsed dimensions and canon_tag match STATUS; rank==m ⇒ no left kernel to project sigmas onto.

### Verdict: **CLOSED**
Full rank. Even a defect would only justify more work if it touched decryption algebra; none exists. CF-T3 already closed sigma-only structure.

### Artifacts
| Path | SHA-256 |
|------|---------|
| `probes/qp-05/qp05_h_rank.cpp` | `9bdff0713982d23cf66a40883f81af8dd0d0f729c7757e6d2b3f22278511fac7` |
| `probes/qp-05/qp05_h_rank.out` | `09d2e6c5c249e43c0ab23ca295e1a7e8d902b3415c6c26181df26d800cde0b69` |
| `probes/qp-05/qp05_h_rank.json` | `66662a12789bf78fe3901f72ea8e64378ad568eb8249249a574ba05ded8f4b1f` |

---

## QP-06 — Deterministic producer / source conformance

### Hypothesis
Active artifacts contain a deterministic field that pinned `071b0e9` cannot produce → unpublished generator.

### Exact inputs
- Active challenge files + `pk.raw`
- Parser: `local-corpus/deep_wire_audit.py`
- Pinned matrix/encrypt conventions (`mixed_weight`, ztag domain, v3 headers)

### Smallest reproducible command
```bash
cd "archive/legacy-probes/qp-06"
python3 qp06_conformance.py
```

### Evidence (all match after correct expectations)
- File SHA-256s: secret.ct, pk.bin, params.json, manifest.json, pk.raw
- H_digest recomputes; UBK perm/inv; omega order; powg_B structure
- ztag_bad=0; base=44; unique nonces=44; edges=1829; trailing=0
- `c0`: vector **present** but **all values zero** (stock `encrypt.hpp` zeros(S)); matches STATUS `c0_nonzero=0`
- H column weights `min=192 max=193` via pinned `mixed_weight(h_col_wt=192)` — **not** a producer mismatch
- params.json encodings = pvac-v3 / bounty-v2

### Verdict: **CLOSED**
`mismatch_count=0`. Secret PRF internals remain un-fingerprintable without sk.

### Artifact
- `probes/qp-06/qp06_conformance.json`
  SHA-256: `84443e90924846633a596016adbcbade3fb06a3b7e8fff709a3a0954d4998752`

---

## QP-07 — Incremental public delta (anchors only)

### Hypothesis
Public surface moved past NP-01 snapshot anchors → worth a delta scan.

### Anchors (plan) vs observed

| Anchor | Plan | Observed | Changed? |
|--------|------|----------|----------|
| challenge HEAD | `0d08e962…` | `0d08e962…` | no |
| challenge forks | 26 | 26 | no |
| challenge PRs | 3 | **4** | **yes** |
| PVAC pinned | `071b0e9…` | `071b0e9…` | no |
| PVAC open PRs | 2 | 2 (#499,#500) | no |
| PVAC issues | #501–#503 | still open | no |

### Delta scan (because PR count changed)
New relative to prior inventory:
- **PR#4** `nxpath` “Enhance/robust tools” — **closed**, analysis/tools only
- PR#3 `ifeoluwaaj` analysis tools (open)
- PR#1 rename joke (open)

Raw artifact check (active binding):
```text
PR#4 secret.ct / pk.bin → exact active hashes
PR#3 secret.ct / pk.bin → exact active hashes
```

Fork HEADs sampled: no unique active-bound secret material (pk/ct either active match or empty/missing).

### Verdict: **CLOSED_TRIVIAL_DELTA**
Anchor change was PR inventory only; no new unique active-bound objects.

### Artifacts
| Path | SHA-256 |
|------|---------|
| `probes/qp-07/qp07_anchor_compare.json` | `6279c67b237b2841fc8285d26575f60b2b0c823f8dca7fa0e43bc48f233f7c79` |
| `probes/qp-07/qp07_delta.json` | `0547611dadf787f86cf1ea064ba90df7f2694ca69d0196ee8b4ba10cf350d570` |
| `probes/qp-07/qp07_pr_artifact_raw_check.json` | (raw PR#3/#4 active hash confirmation) |
| `probes/qp-07/challenge-prs.json` | `686bed9a1e5907faa5c87825ee470adf7a24dd5c4799403cfbc6b02fdadc9c0f` |

---

## Decision tree result (plan §11)

```text
Missing PC/decrypt security source recovered?  NO  (QP-01 CLOSED)
Toeplitz full == 127-bit truncated?            YES (QP-02 PROVEN)
Combined active-seed secret rank <4096?        NO  (QP-03 CLOSED @ 4096)
Same-key toy partial-key verifier?             SKIP (QP-04)
Active H defect touches decryption?            NO  (QP-05 full rank)
Deterministic fields contradict pinned source? NO  (QP-06 CLOSED)
=> no current public-only local recovery path from these probes
```

## Blocker unchanged

```text
v = N0*x0 + N1*x1 mod p
x_i = R_i^-1
R_i = PRF(prf_k, lpn_s, public_seed_i)   # 256-bit key + 4096-bit LPN still both required
PC_i = [center(x_i)]G + [rho_i]H         # rho keyed; no public R
```

Producer path remains `keygen()` + `enc_text()` only.

## Explicit non-claims
- **Not SOLVED**
- QP-02 truncation is **not** a break of AES-LPN-PRF secrecy
- Did not reopen CF-T1..T8 / NP-01..05 / NP-07 closed routes
- No wallet/mnemonic/brute force; no wallet interaction

## Reopen only if (unchanged + QP notes)
1. New active-bound public artifact (QP-07 watcher)
2. AES-LPN-PRF / PC opening break with recovered source (QP-01 residual: private tests)
3. Secret reuse with decryptable artifact
4. Ordinary-BASE bug on enc_text path
5. New public equations reducing below 256-bit prf_k (QP-03/04 closed for current public data)

## FYI (ponytail lite)
QP-03 full 8-key recompute is ~4–5 min pure Python/AES; a C++ AES-NI rank helper would be faster if this probe is re-run often — not needed for the closed verdict already obtained.

---

**Report path:** `../EXECUTOR_RESULTS_AFTER_NP07.md`
**Canonical verifier files not modified:** STATUS.md, RESULTS.md, solve-octra-audit-log.md, NEXT_PLAN*.md
