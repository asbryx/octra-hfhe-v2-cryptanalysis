> **Historical snapshot.** This file preserves an earlier experiment record. Some commit labels, checkout hashes, local paths, and broad verdict wording were later corrected or narrowed. Use `../STATUS.md` and `../research/final-exhaustion.md` as authoritative.

# Solve Octra - Full Public Audit Log

## 1. Scope and Authorization

Target public challenge:

- Organizer: Octra Labs / `@octra`.
- Public announcement: `https://x.com/octra/status/2075336875322032268`.
- Target address: `octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ`.
- Challenge repository: `https://github.com/octra-labs/hfhe-challenge`.
- Pinned implementation: `https://github.com/octra-labs/pvac_hfhe_cpp` at commit `071b0e909c119de815e284b347c4bd979cb59ef3`.

The work below uses public source, public repository history, publicly accessible read-only RPC calls, and local artifact parsing only. It does not submit transactions, move funds, use unrelated credentials, or use the historical key material from other test bounties.

## 2. Executive Result

No active-target plaintext, mnemonic, private key, or reproducible public-only recovery method was found.

This is not a proof that no future bug exists. It is a record that the practical public paths tested so far do not isolate the values needed to decode the active `secret.ct` bundle.

The concrete remaining blocker is the per-layer field value `R`.

For every base layer, public edge data gives a value proportional to `R`, while recovering a plaintext block needs division by that same unknown `R`. `R` is derived from secret PRF material plus a secret LPN vector. The active wire format no longer contains the prior public verification value (`R_com`) that made guessed plaintext testable offline.

## 3. Active Artifact Inventory

Active repository commit:

- `0d08e9622921e5930175a660df0061a65548972f`.

Active public file hashes:

| File | SHA-256 |
|---|---|
| `secret.ct` | `5da7f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab` |
| `pk.bin` | `1e788edff9dea19a782defae053f3757ccf5edd41cd3e24ae44e1496045e9410` |
| `params.json` | `24bf1290b32f6159a95ab5a8428fcd6bd5c91c903efb77defda1bdbdda397d80` |
| `manifest.json` | `0cbda19f5ff723ac2586e769cbf3b26c178066f4ae1602b40a2404e7d99cc18c` |

Public format facts:

- `secret.ct` starts with `OCTRA-HFHE-BTY02`.
- It contains 22 serialized ciphertext objects.
- Every object has `slots = 1` and exactly two BASE layers.
- The first object is the encrypted byte length.
- The other 21 objects are 15-byte packed text blocks.
- Therefore the plaintext byte length is in the range 301 through 315 bytes.
- The active parameters are `B=337`, `m_bits=8192`, `n_bits=16384`, `lpn_n=4096`, `lpn_t=16384`, and LPN error rate `1/8`.

The length is the only confirmed plaintext metadata leak from the active ciphertext count. It does not identify a key format or a plaintext candidate uniquely.

## 4. Exact Generation Flow

The active generator source is `source/hfhe_bounty_artifact.cpp`.

The relevant flow is:

```text
challenge_private/plaintext.txt
  -> keygen(prm, pk, sk)
  -> enc_text(pk, sk, plain)
  -> serialize pk.bin / secret.ct
  -> challenge_private/sk.bin
```

Important source facts:

- The active generator reads `challenge_private/plaintext.txt`; it is not present in the public repository.
- It writes `challenge_private/sk.bin`; it is not present in the public repository.
- It calls `keygen(prm, pk, sk)`, not `keygen_from_seed(...)`.
- `keygen(...)` gets `canon_tag`, the PRF key, field generators, and the LPN vector from the system CSPRNG.
- `keygen_from_seed(...)` exists elsewhere in the PVAC code, but is not used by the active bounty generator.
- Therefore the target wallet private key is not evidenced to be the source of the HFHE secret key.
- The target address appears in the repository only in the README revision that introduced the active artifact, not in `secret.ct`, `pk.bin`, the generator call path, or the active key derivation.

## 5. Exact Encryption and Decryption Algebra

### Text packing

`include/pvac/utils/text.hpp` does the following:

```text
cipher[0] = encrypt(message length)
cipher[1..] = encrypt successive 15-byte little-endian field elements
```

Text blocks start with `depth_hint = 2` and increment for each block. This explains why public edge counts increase over the ciphertext sequence.

### Wrapped block construction

For a plaintext field element `v`, `enc_fp_wrapped_depth` samples a nonzero random field mask `m` and produces:

```text
layer 0 encrypts v + m
layer 1 encrypts -m
combined ciphertext represents v
```

A BASE layer has public numerator:

```text
N(layer) = sum(sign(edge) * edge.weight * powg_B[edge.index])
```

Its hidden relation is:

```text
N(layer) = R(layer) * layer_value
```

Thus a two-layer block is:

```text
v = N0 / R0 + N1 / R1
```

The numerator values are public. `R0` and `R1` are not public.

### Decryption code

`include/pvac/ops/decrypt.hpp` computes every layer `R`, takes its field inverse, and applies that inverse to each edge contribution. There is no alternate public decryption branch.

## 6. What Produces R

The relevant code is `include/pvac/crypto/lpn.hpp`.

For each PRF domain:

1. Derive an AES-256 key from:
   - 256-bit `sk.prf_k`,
   - public `canon_tag`,
   - public `H_digest`,
   - public layer seed (`ztag`, nonce low, nonce high),
   - domain label.
2. Generate LPN rows using AES-CTR.
3. Compute each LPN output bit using the unknown 4096-bit `sk.lpn_s_bits`, then add Bernoulli error with probability 1/8.
4. Apply a Toeplitz map to produce a 127-bit field element.
5. Multiply three independent domain outputs to form `R`.

In simplified form:

```text
R = PRF_R1(secret, public seed)
  * PRF_R2(secret, public seed)
  * PRF_R3(secret, public seed)
```

The active artifact publishes the seed but not the 256-bit PRF key or 4096-bit LPN vector. It also does not publish public `(A, y)` samples in a form that enables an LPN solve.

## 7. Serialization Audit

The active serializer is `source/pvac_artifact_serialize.hpp`.

Verified properties:

- Exact wire version is `PVAC` version `0x03`.
- Reader rejects versions other than v3. There is no public v1/v2 parser downgrade path.
- BASE layers serialize only:
  - rule,
  - `ztag`,
  - nonce low/high,
  - PC points.
- `R_com` is not serialized in v3.
- Cipher edges serialize layer ID, index, sign, field weights, and sigma bit vectors.
- `pk.bin` serializes a compressed public key containing public matrix data, UBK permutation data, field generator powers, and metadata. It does not serialize `sk.prf_k` or `sk.lpn_s_bits`.
- The public parser accepts the active artifact and validates its structure.

Additional invariant checks executed against the active artifact:

- All public BASE-layer `ztag` values recompute correctly from public `canon_tag` and nonce.
- All public field encodings parsed in the artifact are canonical under the current wire format.
- No malformed layer rule, invalid point encoding, invalid edge index, or trailing data was found.

## 8. V1 Versus V2

The repository contains a canceled v1 package with `seed.ct` and a different target address.

V1 was vulnerable because `R_com` included a commitment/check value that allowed structured plaintext guesses to be tested offline. The repository explicitly documents that this was the reason v1 was canceled.

Relevant historical change:

- Older `compute_R_com_base` hashed actual `R` slot values.
- Current source no longer includes those slot values in that hash path.
- Active v3 serialization then removes `R_com` from the public wire format entirely.

This closes the fast candidate verifier that would have made a mnemonic/key-format search realistic.

The v1 artifact, its wallet address, its plaintext type, and its source are distinct from the active v2 target. It is not evidence that an active-target key can be derived.

## 9. Git History and Artifact Provenance

Full reachable challenge history was checked.

Important commits:

| Commit | Meaning | `pk.bin` SHA-256 | `secret.ct` SHA-256 | Objects |
|---|---|---|---|---|
| `08bf879` | initial v2 update | `ad5f...a865` | `8f38...3300` | 9 |
| `e4645c9` | published v2 update | `2ebc...c003` | `1f48...56d4` | 9 |
| `88a72b7` | active v2 artifact introduced | `1e78...9410` | `5da7...fbab` | 22 |
| `841504a` | same active artifact | same | same | 22 |
| `547271b` | same active artifact | same | same | 22 |
| `0d08e96` | current README revision | same | same | 22 |

Findings:

- The active artifact begins at `88a72b7`.
- Earlier v2 artifact pairs are different public keys and different ciphertexts, not a second encryption under the active key.
- The current public upstream refs were `main` and tag `v2_fix`.
- `git fsck --full --no-reflogs --unreachable` found no dangling reachable public object.
- The complete reachable object database contained 67 objects. No active plaintext, active secret key, mnemonic, or generator input was found.
- Forks checked only carried existing commits or README edits; no active-target linked secret artifact was found.

A separate PVAC repository directory `bounty2_data` contains its own test/demo `sk.bin`. It has a different public key and different ciphertext hashes. It was identified as unrelated and not used for the active target.

## 10. Public Chain and RPC Audit

Read-only RPC checks for the target address found:

```text
balance: 500000 OCT
account nonce: 0
transactions: one inbound funding transaction
registered public key: none
registered view key: none
registered PVAC public key: none
encrypted balance/cipher: none
```

The sole public transaction is an inbound funding transfer:

```text
ad1af0cf96a12105bb112b0f3f7275e8fbd713e2f6966d886f5ec2c04e514898
```

The target has not sent a transaction, so there is no target signature/public key to inspect.

Octra addresses are derived as:

```text
oct + Base58(SHA-256(Ed25519 public key))
```

That address construction is one-way. The target address alone does not expose the public key or the private key.

## 11. Pedersen and Ristretto Audit

PC points in each BASE layer represent a Pedersen commitment to `R^-1` plus a secret-derived blinding scalar:

```text
PC = [R^-1]G + [rho]H
```

where `rho` is derived from `sk.prf_k` and the public layer nonce.

Methods and results:

1. Parsed all 44 PC points using the PVAC source decoder.
   - Result: all 44 decoded successfully.

2. Parsed all 44 PC points with independent `curve25519-dalek`.
   - Result: all 44 decoded as valid Ristretto points.

3. Cross-checked PVAC group constants and commitment arithmetic against `curve25519-dalek`.
   - PVAC `G` exactly equals the standard Ristretto basepoint.
   - PVAC `H` decodes as a valid Ristretto point in dalek.
   - A sample PVAC commitment for `7G + 11H` exactly matches dalek arithmetic.

4. Checked whether `H` had a trivial small relation to `G`.
   - Exhaustive scalar multiplication search for `H = kG` over `0 <= k < 1,000,000` found no match.
   - This does not prove there is no large relation, but rules out the immediately exploitable small-scalar case.

5. Investigated a reported concern about the Elligator formula used to derive `H`.
   - The exact C++ source uses `1 - d^2`, not `(1-d)^2`.
   - The initial concern was a reading error and is not an active artifact flaw.

Conclusion: public PC values do not currently produce `R^-1` or plaintext without a discrete-log/blinding break.

## 12. Field and Scalar Arithmetic Audit

Field modulus:

```text
p = 2^127 - 1
```

Methods and results:

- 256 random field multiplications matched independent Python big-integer modular arithmetic.
- The repository field core suite passed:
  - add/sub,
  - multiplication associativity,
  - inversion,
  - Fermat identities.
- 256 scalar reductions modulo the Ristretto scalar order matched independent Python big-integer arithmetic.
- No non-canonical active ciphertext field encodings were found.

Conclusion: no arithmetic mismatch was found that changes public numerator interpretation or reveals a layer inverse.

## 13. Hash, AES, and Toeplitz Audit

### SHA-256

The custom SHA-256 implementation matched Python `hashlib` for:

- empty input,
- `abc`,
- bytes 0 through 255.

### AES-256 CTR

Methods and results:

- Repository AES CTR test passed FIPS-style vector, consistency, nonce separation, key separation, and bounded sampling checks.
- Direct AES output for a fixed AES-256 key/counter exactly matched OpenSSL AES-256 ECB output for the zero block.

### Toeplitz

The scalar GF(2) convolution and the PCLMUL implementation were compared on 64 deterministic vectors.

Result:

```text
toeplitz_scalar_and_clmul_match
```

### PRF suite

The repository PRF test passed:

- SHA-256 vector,
- XOF deterministic replay and domain separation,
- separate PRF R domains.

Conclusion: no PRF implementation discrepancy was found that turns public seed data into a layer value.

## 14. Public Edge and R-Squared Attempts

Tested public edge structures include:

- repeated index checks,
- opposite-sign same-index checks,
- same-layer and cross-layer candidate sums,
- signed edge numerator equations,
- square-root candidates in the field,
- algebraic combinations intended to isolate `R^2`.

Observations:

- Some same-index/opposite-sign patterns exist after edge reduction, but they are not a unique `R^2` oracle.
- They produce many random square-root candidates rather than a single verifiable layer inverse.
- Combining those candidates with the encrypted length did not yield a valid unique value in the known 301-315 range.
- Public edge counts match the text depth/noise schedule. They reveal depth progression, not plaintext bytes.
- Edge count growth comes from the public `entropy::Budget` formula and randomized collision/reduction behavior; it is not a content-dependent encoding leak.

The historical repository `bounty2` R-squared finding applies to a different test setup and not to the active 22-object target.

## 15. Native-Recrypt Findings

Public PRs and issue material describe two real defects in native-recrypt proof/transcript code at the pinned commit:

- PR #499: a native-reset statement digest could act as a candidate oracle for low-entropy hidden coefficients.
- PR #500: a native SHA-256 trace proof did not fully bind its claimed digest.
- Issue #502 independently reproduced them and evaluated confidentiality impact.

Why they do not currently apply to `secret.ct`:

- Active `secret.ct` is produced directly by `enc_text`.
- It contains ordinary BASE layers and edges only.
- It does not serialize a `NatKey`, native-reset transcript, hidden-coefficient statement digest, or native runtime proof.
- The public reproduction report explicitly states that its forged native-key route did not recover plaintext from the bounty artifact.

These are implementation findings, not an active-target recovery path.

## 16. Methods Considered but Not Used

The following were intentionally not used because they are not evidence of a valid active-target solution:

- Historical private keys/credentials unrelated to the active target.
- The unrelated `bounty2_data/sk.bin` test key.
- Attempts to submit transactions or move target funds.
- Guessing a private key/mnemonic without an oracle.
- Brute-force of BIP39/private-key spaces.

Estimated brute-force scale:

| Search space | At 10^12 guesses/sec |
|---|---|
| 12-word BIP39 entropy (2^128) | about 10^19 years |
| 24-word BIP39 or 256-bit key (2^256) | about 10^57 years |

The v2 format additionally lacks a fast offline candidate verifier.

## 17. Remaining Possible Paths

The public work does not show a practical next local computation. A real recovery would need a new condition such as:

1. An additional organizer artifact linked to the active `pk.bin`/`secret.ct` pair.
2. A public verifier/oracle that leaks a meaningful candidate-validity bit.
3. A generator-side leak: plaintext, `sk.bin`, CSPRNG state, CI output, logs, or accidental backup.
4. A demonstrated break in the exact AES/LPN/PRF construction.
5. A demonstrated Pedersen/Ristretto opening break that applies to the exact PC values.
6. A demonstrated secret reuse across the active artifact and another artifact.

None of those conditions has been found in the public material examined.

## 18. Final Current Status

Status: not solved.

The active artifact is internally consistent under:

- official serialization and public-audit checks,
- independent field arithmetic checks,
- independent scalar checks,
- independent Ristretto point and commitment checks,
- SHA-256 checks,
- AES OpenSSL cross-check,
- Toeplitz scalar/PCLMUL cross-check,
- exact Git history/hash comparisons,
- read-only target account/RPC inspection.

The direct blocker remains `R0` and `R1` for every wrapped block. The public artifact exposes their multiplication with layer values but not a way to obtain their inverses.

## 19. Local Verification Notes

Temporary local helpers were used for narrow checks and then removed. They included:

- artifact history hash comparison,
- field multiplication and scalar reduction comparisons,
- SHA-256 vectors,
- AES output comparison against OpenSSL,
- Toeplitz scalar/PCLMUL comparison,
- Ristretto PC and group arithmetic comparison via `curve25519-dalek`,
- active artifact point/ztag invariants.

The standard `make test` command could not run in this environment because `make` is not installed. Individual relevant test files were compiled with LLVM/clang where feasible and completed successfully.


---

# Continuation Findings (session Grok-4.5)

## Continuation Finding CF-T1

Date: 2026-07-10
Hypothesis: Compressed pk.bin may contain physical bytes after logical range-decoder EOF that official decoder ignores, possibly structured hidden data.
Exact target input: active pk.bin SHA-256 1e788edff9dea19a782defae053f3757ccf5edd41cd3e24ae44e1496045e9410
Method:
1. Official C++ probe local-work/pk_compress_probe.cpp using pvac_compress.hpp.
2. Independent Rust boundary decoder local-temp/hfhe_unpack_boundary.rs.
3. Truncation/mutation of packed end bytes; re-unpack and compare raw SHA-256.
Expected success signal: nonzero ignored suffix with structured content, or truncatable suffix preserving raw 67e8538a2a47dfc1539d2777aa36488654b1c92265be08ed941f251a08c2ce28.
Observed result:
- packed_file_length=3042901
- compressed_payload_length=3042896
- declared_raw_length=17110454
- decoder_src_pos_after_expected_raw=3042896
- decoder_src_pos_after_eof=3042896
- physical_bytes_remaining_after_logical_eof=0
- remaining_suffix_len=0
- official: declared=17110454 decoded=17110454 consumed=3042896 payload=3042896 unread=0 repack_exact=1
- trunc_last_1..8: unpack fails (late eof / assert)
- mut_last / mut_near_end: unpack fails or yields different raw hash (bytes not ignored)
Independent verification: official unpack+repack exact match; independent Rust EOF pos equals payload end; raw SHA matches expected.
Verdict: CLOSED
Reproduction command:
```
local-work/pk-compress-probe.exe upstream/hfhe-challenge/pk.bin
export PATH="/c/Users/daniel/.cargo/bin:$PATH"
rustc --edition=2021 -O local-temp/hfhe_unpack_boundary.rs -o local-temp/hfhe_unpack_boundary.exe
local-temp/hfhe_unpack_boundary.exe upstream/hfhe-challenge/pk.bin
```
Output digest/path: stdout; raw local-temp/hfhe_boundary_original.raw sha256=67e8538a...ce28
Next dependency: none for compression suffix.

## Continuation Finding CF-T2

Date: 2026-07-10
Hypothesis: Unique fork commits (nxpath, Eienel, others) introduce target-bound secret material or alternate active artifacts.
Exact target input: nxpath@8a8df807..., Eienel@80317a318..., active hashes.
Method: merge-base vs upstream 0d08e962...; unique commits; name-status; keyword scan; content hash pk/secret at HEAD.
Expected success signal: unique blob with active-linked sk.bin/plaintext or different active ciphertext under same key.
Observed result:
- nxpath: 1 unique commit, tooling only. pk/secret content hashes == active.
- Eienel: 12 unique commits, analysis docs/tools/writeups only; records failed attacks; same active pk/ct hashes.
- pymparticles, Yanu403: README-only; active pk/ct hashes.
- Missing-upstream forks mostly v1 epoch 900255d, not active pair.
- No unique sk.bin/plaintext/alternate active ciphertext blob.
Independent verification: git show HEAD:pk.bin|sha256sum and secret.ct on forks match active.
Verdict: CLOSED
Reproduction command: git log/diff/name-status and content sha256 on fork bare repos under local-work/forks/
Output digest/path: session terminal
Next dependency: none from forks.

## Continuation Finding CF-T3

Date: 2026-07-10
Hypothesis: Perfect public signal/noise graph grouping yields plaintext or removes unknown R.
Exact target input: bounty2_data a.ct/b.ct; scripts local-temp/pvac-v2-r-prf-audit.py and local-temp/toy_graph_bestcase.py
Method: reproduce script flags; best-case residual with secret used only as ground truth.
Expected success signal: public-only plain or R from grouped equations.
Observed result:
- Reproduced: signal_is_R_times_plain=True, N2=True, N3=False, r2_pairs=0
- N_noise==0 and N_sig8==N_all for each toy layer: perfect grouping recovers only already-public full numerator N
- N2 = R * secret_delta still needs secret; N3 partition incomplete; r2_pairs=0
- Script uses sk for R/delta/plain labels; proposed public residual still needs R
- Active wrapped blocks still have independent R0,R1 and mask m
Independent verification: rerun both scripts from upstream/pvac_hfhe_cpp
Verdict: CLOSED for target-scale graph classification recovery path
Reproduction command:
```
cd upstream/pvac_hfhe_cpp
python local-temp/pvac-v2-r-prf-audit.py
python local-temp/toy_graph_bestcase.py
```
Output digest/path: stdout
Next dependency: reopen only if public oracle for R or delta appears.

## Continuation Finding CF-T4

Date: 2026-07-10
Hypothesis: Public wrapped-PC combination is a true/false candidate verifier.
Exact target input: sc_from_fp_signed / pedersen_commit / compute_layer_PC; local-temp/wrapped_pc_delta_probe.py
Method: delta(N,x) distribution; wrapped true/false scalar carry; rho blinding model.
Expected success signal: deterministic public invariant true always / false never without R/rho/m/sk.
Observed result:
- random delta zero_rate=0.0000 over 2000 samples
- scalar carry_true==0: 0/500; false hits 0 over 500*4
- D(v) retains unknown (N0*rho0+N1*rho1)H; 44 unique nonces => independent rho
Verdict: CLOSED
Reproduction command: python local-temp/wrapped_pc_delta_probe.py
Output digest/path: stdout
Next dependency: reopen only if rho relation or H~G trapdoor found.

## Continuation Finding CF-T5a

Date: 2026-07-10
Hypothesis: Active 44 BASE layers share rho inputs enabling PC cancellation.
Exact target input: 44 nonces from local-work/probe-pr2.out
Method: unique (nonce.lo, nonce.hi, slot=0)
Observed result: 44/44 unique rho input tuples; H domain sha256(a225b6f0ee7a6e8bd510a1a2a8a4707e1b28e37362b05965538ac8a605e9da8b)
Verdict: CLOSED for rho-input collision
Reproduction command: parse probe-pr2.out T=lo:hi pairs
Output digest/path: probe-pr2.out
Next dependency: PRF domain/AES-counter overlap exact audit; producer RNG evidence; new organizer artifact.

## Phase 0 re-lock (this session)

- challenge HEAD: 0d08e9622921e5930175a660df0061a65548972f
- pvac HEAD: 071b0e909c119de815e284b347c4bd979cb59ef3
- secret.ct / pk.bin / params.json / manifest.json: MATCH active table
- magic OCTRA-HFHE-BTY02 confirmed

## Status after CF-T1..T5a

Not SOLVED. Blockers unchanged: unknown R0,R1 and wrap mask m; PC blinded by independent rho; no public candidate verifier; no ignored compression suffix; no fork secret leak.


## Continuation Finding CF-T5b

Date: 2026-07-10
Hypothesis: PRF domain/AES-counter structural collision enables stream reuse without sk.prf_k.
Exact target input: Dom::* strings in types.hpp; derive_aes_key/prf_R_core in lpn.hpp; active 44 nonces from seed_pc_probe.
Method: fnv1a all domains; uniqueness of (nonce,dom_hash) public tuples; TOEP key-sharing analysis; length-boundary check.
Expected success signal: domain hash collision or same AES key+overlapping counter precondition present.
Observed result:
- all 16 domain fnv1a hashes unique (no collisions)
- R1/R2/R3 and noise1/2/3 hashes unique
- AES LPN keys include dom_hash in SHA-256 input => different domains => different keys for same seed
- TOEP: one key per seed (domain TOEP), nonce ^= fnv1a(R_dom); nonces differ without domain collision
- SHA domain is u64(fnv1a(string)), not raw string concat => no length-boundary ambiguity
- active: 44 unique nonces; 132 unique (nonce,R_dom) public tuples; 132 unique noise tuples
- counter_overlap_precondition=absent
Independent verification: python local-temp/prf_domain_audit.py; source lpn.hpp derive_aes_key
Verdict: CLOSED
Reproduction command: python local-temp/prf_domain_audit.py
Output digest/path: stdout
Next dependency: none without secret or new domain bug.

## Continuation Finding CF-T5c

Date: 2026-07-10
Hypothesis: Cross-epoch key/nonce/CSPRNG reuse between active artifact and public epochs (e4645c9, 08bf879, bounty2/3, v1 orphan).
Exact target input: seed_pc_probe dumps of active/e464/08bf; pk hashes; bounty2 sk.
Method: extract canon_tag, H_digest, all layer nonces/ztags/PC0; set intersection; compare pk/sk epochs.
Expected success signal: shared canon_tag/H or shared nonce under related key material.
Observed result:
- active: canon=531565633433868593 Hdig=601435f4977dd2a0...; 44 unique nonces/ztags/pc0
- e4645c9 (older v2): different canon/H; 18 unique nonces; intersect with active nonces/ztags/pcs = 0
- 08bf879: different canon/H; intersect with active and e464 = 0
- bounty2/bounty3 pk SHA differ from active; bounty2 sk is demo key (different pk)
- orphan-fa6 pk SHA = v1 epoch 580b6fcf... (unrelated)
- generator source only calls keygen(...), never keygen_from_seed
- csprng path: OS getrandom/BCrypt/arc4random; no user-space PRNG state; no public evidence of weak fallback on producer
Independent verification: local-work/seed_pc_probe.exe on epoch dirs; git history pk hashes
Verdict: CLOSED (no cross-epoch reuse fingerprint)
Reproduction command:
```
local-work/seed_pc_probe.exe upstream/hfhe-challenge
local-work/seed_pc_probe.exe local-work/epochs/e4645c9
local-work/seed_pc_probe.exe local-work/epochs/08bf879
```
Output digest/path: local-work/seeds_*.txt
Next dependency: none unless new artifact with matching canon/nonce appears.

## Continuation Finding CF-T5d

Date: 2026-07-10
Hypothesis: Public CI/release/PR/code-search surfaces hold active-bound secret or call-path bug on ordinary BASE enc_text.
Exact target input: local API dumps under local-work; release-v2_fix; search-code hashes; hfhe_bounty_artifact.cpp.
Method: keyword/size scan of issues/PRs; release assets; GitHub code search results for active hashes/address; confirm generator call path.
Expected success signal: sk.bin/plaintext attachment or BASE-path confidentiality bug reaching secret.ct production.
Observed result:
- api-challenge-runs.jsonl and api-pvac-runs.jsonl empty (no public Actions logs)
- release v2_fix present; no secret assets beyond public challenge files in prior inventory
- code search for active pk/ct hashes hits only SHA256SUMS in challenge repo
- address search hits README only
- generator path confirmed: keygen + enc_text only (lines 165/350/431)
- PR/issue material remains analysis/docs or historical native-recrypt (already closed for ordinary BASE)
Independent verification: local JSON dumps + source rg
Verdict: CLOSED for currently available public hosting surfaces
Reproduction command: inspect local-work/api-* and release-v2_fix.json
Output digest/path: session
Next dependency: new organizer-published artifact or new BASE-path bug report.

## Decision tree status (this session)

```
hashes/commits match          -> yes
hidden compression suffix     -> CLOSED CF-T1
PC true/false verifier        -> CLOSED CF-T4
rho input collision           -> CLOSED CF-T5a
fork secret leak              -> CLOSED CF-T2
graph best-case removes R     -> CLOSED CF-T3
cross-epoch reuse             -> CLOSED CF-T5c
PRF domain/counter collision  -> CLOSED CF-T5b
public CI/release secret      -> CLOSED CF-T5d
new ordinary-BASE bug         -> not found
=> public paths in operational plan exhausted for current evidence set
```

## Honest stop condition

Not SOLVED. No reproducible public-only recovery of active plaintext.

Remaining conditions that could reopen (exact):
1. New public artifact bound to active pk.bin/secret.ct (sk, plaintext, CSPRNG log, producer binary with weak RNG).
2. New cryptographic break of AES-LPN-PRF or Pedersen/Ristretto PC opening under exact parameters.
3. Demonstrated secret reuse between active key and another decryptable public artifact.
4. New ordinary-BASE confidentiality bug that reaches enc_text -> PVAC v3 secret.ct production path.

Blocked values remain R0,R1 (and wrap mask m) per cipher; 256-bit prf_k + 4096-bit LPN vector not public.


## Continuation Finding CF-T6

Date: 2026-07-10
Hypothesis: Active secret.ct has non-BASE layers, trailing bytes, zero PC, duplicate PC, or zero numerators exploitable publicly.
Exact target input: active artifact via local-work/active_edge_probe.exe
Method: full parse all 22 ciphers; count BASE/non-BASE; PC uniqueness; c0; bundle EOF; opposite-sign same-index groups.
Expected success signal: native layer, trailing payload, identity PC, or algebraic zero leak.
Observed result:
- SUMMARY base=44 non_base=0 total_edges=1829 unique_pc=44 dup_pc=0 zero_pc=0
- opp_same_idx_groups=56 (exists but gives no R without secret)
- c0_nonzero=0 (all c0 zero as expected)
- bytes_left_after_bundle=0 consumed=1963107 file=1963107
- zero_numerators=0
Verdict: CLOSED (structure clean; no extra wire leak)
Reproduction: local-work/active_edge_probe.exe upstream/hfhe-challenge
Output: local-work/active_edge.txt

## Continuation Finding CF-T7

Date: 2026-07-10
Hypothesis: Current R_com still binds R values / is on wire / is a candidate oracle for active v3.
Exact target input: compute_R_com_base at pinned commit; git cdc6a52; active seeds.
Method: read hash.hpp; recompute public R_com from (canon,ztag,nonce,slots) only; check wire serialize.
Observed result:
- cdc6a52 (2026-07-07) removed R_slots from R_com hash (oracle hardening)
- current R_com = SHA256(domain||canon||ztag||nonce||slot_count) only — public, independent of R
- v3 write_layer does NOT serialize R_com
- 44 unique public R_com digests (just unique seeds)
- not a plaintext/R verifier
Verdict: CLOSED
Reproduction: git show cdc6a52 -- include/pvac/core/hash.hpp; python recompute from seeds_active.txt

## Continuation Finding CF-T8

Date: 2026-07-10
Hypothesis: wallet-gen / webcli public clones or git unreachable objects hold active-bound secret.
Exact target input: local-work/wallet-gen.git, webcli.git; challenge+pvac fsck.
Method: git grep active address/hashes/BTY02; fsck unreachable.
Observed result:
- wallet-gen/webcli: no hits for active address, active hashes, BTY02, challenge_private
- challenge repo: 42 blobs / 11 commits / 14 trees; sk/plaintext only as source path strings in generator
- fsck: no reported unreachable secret objects in scanned output
Verdict: CLOSED

## HARD STOP — public plan exhausted

Not SOLVED under definition in operational plan.

All decision-tree branches for current public evidence are CLOSED with reproducible probes (CF-T1..T8).

Concrete blocker equation remains:
  v = N0*x0 + N1*x1 mod p
  x_i = R_i^-1 unknown
  PC_i = [center(x_i)]G + [rho_i]H with rho_i keyed by sk.prf_k
  R_i from AES-LPN-PRF(sk.prf_k, sk.lpn_s_bits, public seed)

No public-only procedure recovers x_i or v for the active 22-object BTY02 bundle.

Reopen only if one of the four conditions in CF-T5d status block appears.


## Next Finding NP-01

Date: 2026-07-11
Hypothesis: New public delta (forks/PRs/issues since CF-T8) contains active-bound secret or recovery path.
New prerequisite not covered by CF-T1..T8: GitHub now lists 26 forks (was 22); new issues/PRs exist.
Exact target input: delta forks akidry, ifeoluwaaj, JH-321, k3llgh; challenge issues/PRs 1-3; pvac #503.
Method: freeze old inventory; clone 4 new bare forks; count unique commits vs upstream 0d08e96; hash pk/ct; skim new issues/PRs.
Expected success signal: active-bound artifact/key/log or ordinary-BASE break.
Observed result:
- new_forks=4
- new_unique_commits=0 (all HEAD==0d08e962...)
- new_unique_blobs=0 beyond upstream
- all 4 forks: pk/ct SHA == active
- challenge PR #3 (ifeoluwaaj): analysis tools only (null results)
- challenge issues #1 rename joke, #2 Eienel, #3 analysis
- pvac open: #503 malleability, #502 native-recrypt (already closed for BASE), #501 bounty2 R^2 (not active)
Independent verification: git rev-parse + sha256sum on bare clones
Verdict: CLOSED
Reproduction command: see repository-root/public-delta-20260710.json
Output digest/path: repository-root/public-delta-20260710.json
Next dependency: none from public delta

## Next Finding NP-02

Date: 2026-07-11
Hypothesis: PVAC issue #503 (non-canonical rist_decode) changes interpretation of active PC points.
New prerequisite not covered by CF-T1..T8: issue created 2026-07-10.
Exact target input: pinned 071b0e9; G, H, 44 active PC encodings.
Method: read issue body; reproduce high-bit acceptance; decode+reencode all active points.
Expected success signal: active PC non-canonical / multi-interpretation / public invariant on x or rho.
Observed result:
- issue_repro noncanon_accepted=1 same_point=1 (confirmed)
- SUMMARY total=46 (G+H+44 PC) hi_bit=0 decode_fail=0 reenc_mismatch=0
- all active PC encodings canonical (high bit clear, re-encode equal)
- issue author states not a key recovery break for bounty; path is attacker-supplied encoding / fold_sig, not fixed secret.ct opening
Independent verification: local-work/pc_canon_check.exe
Verdict: CLOSED
Reproduction command: local-work/pc_canon_check.exe
Output digest/path: stdout SUMMARY
Next dependency: none for fixed active bytes

## Next Finding NP-03

Date: 2026-07-11
Hypothesis: corrected finite artifact-derived wallet candidates match announced address.
New prerequisite not covered by CF-T1..T8: Eienel script used wrong ct hash 5da3…; corrected set not logged.
Exact target input: active hashes, H_digest, canon, commits, funding tx, domain labels; TARGET address.
Method: ~99 seeds × 4 transforms (raw ed25519, bip39-12 Octra path, sha256 seed, HMAC Octra seed); address check only.
Expected success signal: exact address match.
Observed result:
- candidate_seeds=99
- approx tests=396
- hits=0
- wrong hash included as control; still no match
Independent verification: python local-work/np03_wallet_candidates.py (pynacl+mnemonic)
Verdict: CLOSED
Reproduction command: python local-work/np03_wallet_candidates.py
Output digest/path: stdout
Next dependency: only reopen with new evidenced candidate family (not generic dict)


## Next Finding NP-04

Date: 2026-07-11
Hypothesis: Historical payload/template lineage uniquely fits active 301-315 byte shape and exposes bounded generation source.
New prerequisite not covered by CF-T1..T8: wallet-gen export format + bounty3 plaintext schema not matrixed against length band.
Exact target input: wallet-gen HEAD export template; bounty2/3 READMEs; active length 301-315; challenge README wording.
Method: measure official export length distribution; measure known short templates; check which can fall in band.
Expected success signal: one exact template+lineage with finite unknown field.
Observed result:
- wallet-gen `octra_wallet_*.txt` export: length 637–656 over 50 random 12w samples — NEVER in 301–315
- bounty3 format `mnemonic: 12w, number: N`: ~90–110 bytes — far below
- short json/key dumps: typically <300
- free-form instruction + mn/key blocks CAN be padded into 301–315, but unknown remains full-entropy mnemonic/key
- README only says "private key and metadata" — no schema
- matrix: archive/payload-template-matrix.csv
Independent verification: python length measurements + wallet-gen server.ts template
Verdict: CLOSED (format knowledge does not reduce to searchable space)
Reproduction command: see payload-template-matrix.csv
Output digest/path: archive/payload-template-matrix.csv
Next dependency: none for format-only; NP-05 only if external statement names exact generator path

## Next Finding NP-05

Date: 2026-07-11
Hypothesis: Wallet-generator provenance ties target address to weak/deterministic source.
New prerequisite: timeline + template from NP-04/07.
Exact target input: wallet-gen history RNG; active publish window 2026-07-09.
Method: review wallet-gen entropy source; correlate with template fit and funding timeline.
Expected success signal: public statement/build/test vector bounding seed family.
Observed result:
- wallet-gen uses `crypto.randomBytes` for entropy (CSPRNG), not weak PRNG
- official export template does not match active length band → active plaintext is NOT stock wallet-gen file export
- no public statement found specifying how bounty plaintext.txt was produced
- no deterministic demo path evidenced for target address
Independent verification: wallet-gen src/server.ts entropy path; length matrix
Verdict: CLOSED
Reproduction command: git show HEAD:src/server.ts in wallet-gen.git (randomBytes + export template)
Output digest/path: STATUS notes
Next dependency: organizer statement or new artifact only

## Next Finding NP-07

Date: 2026-07-11
Hypothesis: Funding tx / announcement metadata exposes generation lineage.
New prerequisite: live RPC access via octrascan rpc.js → https://octra.network/rpc
Exact target input: tx ad1af0cf…; address octC5eR9…
Method: JSON-RPC octra_transaction, octra_balance, octra_transactionsByAddress.
Expected success signal: memo/tool version/linked account narrowing wallet generation.
Observed result:
- funding: confirmed, epoch 1319790, amount 500000 OCT, op_type standard, message=null
- from: oct7xCozDD9JEsbeVpo5C7HXp2BJbKqfmNUHmDDCCTtWcGb
- timestamp 1783630327.265424 → 2026-07-09T20:52:07.265424+00:00
- timeline: e464 v2 publish 20:33Z → funding 20:52Z → active 88a72b7 21:08Z
- balance 500000.000001; account nonce 0; has_public_key false
- no outbound from target; other txs only mention address as call param
- no memo/message/data on funding transfer
Independent verification: curl/python JSON-RPC to https://octra.network/rpc
Verdict: CLOSED
Reproduction command: python JSON-RPC octra_transaction [txhash]
Output digest/path: archive/legacy-probes/funding-tx.json
Next dependency: none
