# Octra HFHE v2 — Reconstruction Audit and Live Delta 019380c

**Date:** 2026-07-11
**Status:** NOT SOLVED
**Scope:** source-first reconstruction of the challenge timeline, active producer/decrypt flow, active wire, prior probes, and the new public LPN corpus at upstream HEAD `019380c97543620091409b0fbf73a8a773a9a0da`.

## Executive verdict

The original target bytes are unchanged and no plaintext, wallet private key, or practical public-only recovery path was found.

The old blocker remains the 44 hidden BASE-layer values `R`, but the public evidence set changed materially on July 11:

- `d9d29d505e2840c0028d7a91a2a8ba59e163b9a4` added 44 target-associated LPN JSONL files;
- `019380c97543620091409b0fbf73a8a773a9a0da` clarified that recovering `S` is an additional side target, while the main bounty still requires the plaintext/wallet payload;
- therefore the prior statement that no public `(A,y)` LPN instance exists is now stale;
- however, the new samples cover only `pvac.prf.r.1`, and recovering `S` alone does not compute `R` under pinned PVAC source.

The largest mistake in prior organization was not the core algebra. It was treating one commit ID as all of: target introduction, activation, announcement snapshot, and current HEAD. These are four distinct anchors.

## 1. Correct commit anchors

| Meaning | Commit | Fact |
|---|---|---|
| Target bytes introduced | `88a72b703f4cdd26b5fe6b3249850c2cbcef3b43` | Current `pk.bin`, `secret.ct`, and target address first appear together |
| Manifest becomes active | `547271bcefb77cc5c4a5bf3dd5d742e6e0ed315b` | Status changes from `pre-release` to `active`; target bytes do not change |
| Announcement snapshot | `0d08e9622921e5930175a660df0061a65548972f` | Last repository commit before the public announcement; README-only change |
| Current upstream HEAD | `019380c97543620091409b0fbf73a8a773a9a0da` | Adds/clarifies the July 11 LPN side target |

Canonical shorthand:

```text
target bytes introduced = 88a72b7
manifest active          = 547271b
announcement snapshot    = 0d08e96
current upstream HEAD    = 019380c
pinned PVAC source       = 071b0e9
```

The tag `v2_fix` is not the live wallet target. It points to `08bf879`, a 9-object, 110-byte pre-release epoch.

## 2. Artifact epochs

| Epoch | First commit | Cipher | Objects | Plaintext status |
|---|---|---|---:|---|
| Canceled v1 | `900255d` | `seed.ct`, wire v2 | 7 | exact 79-byte mnemonic stated publicly |
| Early v2 | `08bf879` | `secret.ct`, wire v3 | 9 | exact 110-byte generated email/secret payload |
| Generic v2 pre-release | `e4645c9` | different `secret.ct` | 9 | external `challenge_private/plaintext.txt` |
| Current target bytes | `88a72b7` | current `secret.ct` | 22 | external private plaintext; inferred 301–315 bytes only under producer provenance |
| Live evidence extension | `d9d29d5` / `019380c` | target bytes unchanged | 22 | 44 LPN R1 sample files added |

Current target hashes remain:

```text
secret.ct  5da7f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab
pk.bin     1e788edff9dea19a782defae053f3757ccf5edd41cd3e24ae44e1496045e9410
pk.raw     67e8538a2a47dfc1539d2777aa36488654b1c92265be08ed941f251a08c2ce28
```

Canonical Git/raw hashes, not CRLF-converted checkout hashes:

```text
params.json    28ea07666fa34935cfa4f46efe96548ee6c9879dcea2c4b10a57b6da95b8c559
manifest.json  97d76005f0f8ffbcc4f04244da43fecfef53811cb24a2bea2d423cd77e594a42
```

The previously recorded `24bf...` and `0cbda...` values are Windows working-tree hashes after line-ending conversion, not canonical upstream object bytes.

## 3. Exact active producer flow

```text
challenge_private/plaintext.txt
  -> raw bytes, no mnemonic/JSON parsing and no trimming
  -> Params(default, noise_entropy_bits=128)
  -> keygen(prm, pk, sk)                 # system CSPRNG
  -> enc_text(pk, sk, plaintext)
       cipher[0]  = wrapped encryption of byte length, depth 0
       cipher[1]  = wrapped 15-byte LE block, depth 2
       ...
       cipher[21] = wrapped final block, depth 22
  -> serialize_pubkey(pk, compressed=true) -> pk.bin
  -> serialize_bundle(ciphertexts)          -> secret.ct
  -> serialize_seckey(sk)                   -> private sk.bin
  -> deserialize and dec_text round-trip verification
```

Important source boundaries:

- producer calls `keygen()`, not `keygen_from_seed()`;
- HFHE `prf_k` and `lpn_s_bits` are independent OS-CSPRNG outputs;
- no evidence links the target wallet private key to the HFHE key generation state;
- wallet key material, if present, is plaintext content, not the seed of the HFHE secret key.

References:

- `hfhe-challenge@019380c/source\hfhe_bounty_artifact.cpp:342`
- `hfhe-challenge@019380c/source\hfhe_bounty_artifact.cpp:350`
- `hfhe-challenge@019380c/source\hfhe_bounty_artifact.cpp:351`
- `hfhe-challenge@019380c/source\hfhe_bounty_artifact.cpp:354`
- `pvac_hfhe_cpp@071b0e9/include\pvac\crypto\keygen.hpp:67`
- `pvac_hfhe_cpp@071b0e9/include\pvac\crypto\keygen.hpp:86`
- `pvac_hfhe_cpp@071b0e9/include\pvac\crypto\keygen.hpp:150`

## 4. Active wire, independently reconstructed

`secret.ct` is canonical and fully consumed:

```text
size                     = 1,963,107 bytes
bundle magic             = OCTRA-HFHE-BTY02
cipher objects           = 22
slots                    = 1 for all objects
layers                   = 44 BASE, 0 PROD/non-BASE
layers per object        = 2
edges                    = 1,829 total; 43..120 per object
nonces                   = 44/44 unique
PC                       = 44/44 unique; one per layer
c0                       = 22 vectors, each exactly [0]
outer/inner trailing     = 0
noncanonical Fp          = 0
invalid sigma padding    = 0
bad ztag                 = 0
R_com bytes on wire      = 0
```

Exact byte accounting:

```text
bundle overhead = 16 magic + 8 count + 22*8 lengths = 200
BASE layer      = 1 rule + 24 seed + 8 PC count + 32 PC = 65
cipher fixed    = 184
edge            = 1071

total = 200 + 22*184 + 1829*1071 = 1,963,107
```

This rules out a hidden serialized `R_com` field or unparsed suffix.

### Length wording correction

Wire alone proves only that there are 22 ciphertext objects. `dec_text()` accepts any decrypted length `0..315` and does not enforce a minimum implied by object count.

The `301..315` interval is valid only after accepting the published producer path `enc_text()`:

```text
22 = 1 + ceil(length / 15)  =>  301 <= length <= 315
```

Therefore this is a **producer-bound inference**, not a parser-only wire invariant.

References:

- `pvac_hfhe_cpp@071b0e9/include\pvac\utils\text.hpp:45`
- `pvac_hfhe_cpp@071b0e9/include\pvac\utils\text.hpp:52`
- `pvac_hfhe_cpp@071b0e9/include\pvac\utils\text.hpp:70`
- `pvac_hfhe_cpp@071b0e9/include\pvac\utils\text.hpp:73`

## 5. Exact decryption algebra

All field equations are in `Fp`, with `p = 2^127 - 1`.

For a public edge `e` in layer `l`, define its signed contribution:

```text
term(e) = sign(e) * e.w[0] * powg_B[e.idx]
N_l     = sum(term(e) for e in layer l)
```

For every BASE layer:

```text
R_l = core_R1(sk, seed_l) * core_R2(sk, seed_l) * core_R3(sk, seed_l)
x_l = inverse(R_l)
```

Target decrypt for one wrapped object is:

```text
v = N_0*x_0 + N_1*x_1 mod p
```

The producer selects a nonzero random mask `m` and creates two independent BASE layers:

```text
N_0 = R_0*(v + m)
N_1 = R_1*(-m)
```

The mask cancels only after each numerator is divided by its own independent `R`.

PC is:

```text
PC_l = [center(R_l^-1)]G + [rho_l]H
rho_l = Reduce(SHA256("pvac.prf.rho" || prf_k || nonce_l || slot))
```

PC is not a direct encoding of `R^-1`; `rho` is keyed and all 44 nonces are unique.

`R_com` requires careful separation:

- it exists in the in-memory `Layer` type;
- current `compute_R_com_base` hashes metadata and slot count, not R values;
- v3 serializer writes no `R_com` bytes;
- parsed layers receive zero/default `R_com`, not a value recovered from the wire.

References:

- `pvac_hfhe_cpp@071b0e9/include\pvac\ops\encrypt.hpp:732`
- `pvac_hfhe_cpp@071b0e9/include\pvac\ops\encrypt.hpp:981`
- `pvac_hfhe_cpp@071b0e9/include\pvac\ops\decrypt.hpp:66`
- `pvac_hfhe_cpp@071b0e9/include\pvac\ops\decrypt.hpp:86`
- `hfhe-challenge@019380c/source\pvac_artifact_serialize.hpp:292`

## 6. New LPN corpus at 019380c

The live repository adds 44 files:

```text
ct00..ct21 x layer 0..1 x slot 0
```

All headers declare:

```text
format    = octra-bounty-target-seed-lpn-ay-v1
domain    = pvac.prf.r.1
n         = 4096
t         = 16384
tau       = 1/8
row_words = 64
```

Inventory:

```text
files                 = 44
equations declared    = 44 * 16,384 = 720,896
total bytes           = 755,745,006
unique seed tuples     = 44
unique public_T values = 44
covered objects        = 0..21
covered layers         = 0,1
covered domains        = R1 only
```

One full file was independently downloaded and checked:

```text
file      = ct00_l0_s0_pvac_prf_r_1.jsonl
sha256    = c6a29620a6f5927c5bdac25eed3c280a0e52bfdfb2d7f893363f7721f1641920
lines     = 16,385 (header + 16,384 rows)
A width   = 512 bytes / 4096 bits
row IDs   = exact 0..16,383
unique A  = 16,384/16,384
y ones    = 8,196 / 16,384
```

### Binding scope

The official verifier reads only the first JSONL line. It checks:

- domain;
- `ztag`;
- nonce low/high;
- `public_T`, recomputed as the public signed layer aggregate.

It does not verify:

- the 16,384 `A,y` rows;
- row count/order;
- that the rows use the target `S`;
- the file name/cipher/layer indices;
- any secret-derived cryptographic binding.

This is why `019380c` changed the README wording from generic “binding” to **public metadata binding**. SHA256SUMS makes committed bytes immutable, while target-secret provenance remains an organizer assertion.

### Why recovering S is not sufficient for plaintext

Pinned source computes:

```text
y_R1  = A_R1 * S xor e_R1
core1 = Toeplitz(top(prf_k, seed, R1), y_R1)
R      = core1 * core2 * core3
```

The new file already publishes `y_R1` directly. Recovering `S` does not reveal:

- keyed Toeplitz `top` for R1;
- R2 or R3 AES rows and `y` values;
- the shared 256-bit `prf_k`;
- PC blinding `rho`.

`prf_k` and `S` are independent CSPRNG outputs in the active `keygen()` path. Therefore:

```text
recover S != recover prf_k
recover S != compute R
recover S != decrypt secret.ct
```

Recovery of `S` would still be a valid side-target result and would reduce the unknown secret state, but the remaining main-bounty obstacle is a generic-looking 256-bit `prf_k` plus its SHA/AES-derived streams.

### Concrete feasibility of the S side target

Assuming all 44 files honestly share one random-dense `S` and Bernoulli noise `tau=1/8`:

```text
n                  = 4,096
samples            = 720,896 = 176*n
expected errors    = 90,112
BSC capacity       = 1 - H2(1/8) = 0.456436
information floor  = about 8,974 samples
```

The corpus is information-rich but computationally hard:

- candidate correlation is an excellent verifier, but searching all `S` remains about `2^4096`;
- an optimistic unlimited-data BKW model bottoms out around `2^425` work with tables around `2^410`, far beyond the available `2^19.46` samples;
- clean-information-set probability is `(7/8)^4096`, giving Prange about `2^791.48` trials and roughly `2^823` bit operations after elimination overhead;
- dense Max-XOR/SAT and message-passing do not gain an initial foothold: rows have weight about 2048 and the factor graph is dense and highly loopy;
- concatenating 44 instances adds only `log2(44)=5.46` bits of data and strong candidate validation; it does not reduce the 4096-bit secret dimension.

Scaled Syndrome Decoding Estimator runs were deliberately discarded: tiny scaled dimensions degenerated to `p=0`/Prange-like parameters, while larger runs exhausted resources before producing an estimate. Extrapolating those scaled outputs would be invalid.

### AES-CTR alignment does not bridge to prf_k

For `lpn_n=4096`, every public `A` row consumes 64 `uint64_t` words. The following `bounded(8)` selector consumes a word from the same R-domain AES-CTR stream. Due to half-block buffering, a published `A` word can be the other half of an AES block whose selector half is hidden on alternating rows.

This does not reveal the hidden half or AES-256 key. Rejection probability for `bounded(8)` is only `2^-61` per attempt, so alignment is almost always predictable but still not a cryptanalytic bridge. Toeplitz uses a fresh AES object and a separately derived `Dom::TOEP` key/nonce; R1/R2/R3 Toeplitz counter ranges do not overlap for the 44 active seeds checked.

## 7. Audit of prior conclusions

### Still valid

- Active producer uses random `keygen()`, not wallet-seeded keygen.
- Wrapped values are two independent BASE layers, not a PROD construction.
- v1 `R_com` plaintext-guess oracle is absent from active v3 wire.
- Active PC encodings are canonical and nonce/rho reuse is absent.
- Public H is full row rank for the measured active matrix.
- O0/O3 deterministic seeded builds produced identical serialized bytes in the tested harness.
- Simple sigma, opposite-sign, and popcount-weight heuristics did not isolate N2/N3 groups.
- Stock wallet-gen export and official webcli schemas do not fit 301–315 bytes exactly.
- No deterministic wallet generation provenance was found.

### Valid only with narrower wording

1. **FV-01**
   - Valid claim: tested sigma and popcount-proxy weight scorers rank true N2/N3 groups near random.
   - Invalid broad claim: all complete public-field ranking/reconstruction methods are closed.
   - The weight scorer was only a popcount proxy of `term.lo ^ term.hi`; it did not implement exact field sum/ratio/collision ranking.
   - `exact_partition_rate=0` was printed as a constant rather than measured.

2. **QP-03 / RR-04**
   - Valid claim: dummy-key matrices over active public seeds behaved generically/full-rank and obeyed the Toeplitz rank formula.
   - Invalid broad claim: exact active-key LPN/Toeplitz rank is known.
   - The active `prf_k` and exact active Toeplitz top remain unknown.

3. **FV-02**
   - Valid claim: no tested O0/O3 byte divergence.
   - Coverage overstatement: the fifth test value was still 64-bit, not a genuine arbitrary 127-bit field value; the numerator digest covered terms, not canonical per-layer aggregate values.

4. **NP-04 / CF-T8**
   - The saved payload matrix omitted official webcli schemas and called them synthetic/short JSON.
   - Recalculation closes the gap but keeps the conclusion: non-HD schemas are about 146–220 bytes; HD schemas about 405–476 bytes; no exact stock schema fits 301–315.

5. **Plaintext length**
   - `301..315` is producer-bound, not wire-only.

6. **R_com**
   - In-memory computed field, parsed default field, and serialized wire bytes must not be conflated.

### Stale due to new public evidence

- “No public `(A,y)` LPN instance exists.”
- “Public evidence is exhausted at challenge HEAD `0d08e96`.”
- “NP-01/RP-07 public delta is closed.”
- Any plan that treats `0d08e96` as current upstream HEAD.

### Incorrect external claims rejected

- Digger analysis using `08bf879`, 79-byte mnemonic assumptions, or `keygen_from_seed` does not target the current bytes.
- PR #3 claim “recovering S allows computing R and decrypting” is not supported by pinned source.
- The verifier does not prove row-level secret binding; it proves public metadata association only.

## 8. Additional exact collision scan

The exact active pair/triple algebra omitted by FV-01 was scanned directly:

```text
pair candidates             = 20,246
pair sum duplicate excess   = 0
pair ratio duplicate excess = 0
zero pair sums              = 0

triple candidates           = 609,751
triple sum duplicate excess = 0
zero triple sums            = 0
```

No trivial equality, duplicate ratio, or zero-sum clue exists in these candidate sets.

Probe:

```text
local-corpus/active_sum_collision.py
SHA-256 9f253efc1bf4b518d8b766659fc162c2f84329f07428d54d87781b7d04cc25e2
```

This closes simple collision tests, not all possible group reconstruction.

## 9. Remaining structured plaintext constraints

If producer provenance is accepted:

```text
q0 = plaintext byte length, 301..315
q1..q21 < 2^120
r = length - 300, with 1 <= r <= 15
q21 < 2^(8*r)
```

These cross-object constraints are stronger than length alone, but still do not solve 44 independent unknown layer inverses. Preserve them as a verifier only after a bounded candidate family for `R`, `prf_k`, or plaintext exists.

## 10. Minimal corrected plan

### P0 — Live corpus integrity, bounded work

Stream all 44 JSONLs once and record:

- SHA-256 against live `SHA256SUMS`;
- exact row count and sequential row IDs;
- 4096-bit row width;
- duplicate rows within/across files;
- header-to-layer metadata match.

Do not treat metadata binding as proof of common secret. Record organizer provenance separately.

### P1 — Exact dependency/bridge proof

Build one small pinned-source harness that consumes published `y_R1[0..126]` and demonstrates:

1. R1 core still changes with `prf_k` because Toeplitz top is keyed;
2. R2/R3 cannot be reconstructed from R1 samples plus `S`;
3. recovering `S` alone does not reproduce any active PC or `R`;
4. a full candidate `(S, prf_k)` can be verified against all public PC/aggregates.

This prevents spending large resources on the wrong dependency.

### P2 — LPN side target only if independently worthwhile

Before BKW/ISD/SAT investment, obtain one of:

- a separate reward/recognition condition for `S` recovery;
- a concrete multi-instance estimator below available compute;
- a source-grounded bridge from `S` to reduced `prf_k`.

Absent one of these, do not launch a large LPN solve merely on the assumption that `S` decrypts the wallet.

### P3 — Main-bounty promotion gate

Promote work only if a new result provides at least one of:

- reduced candidate family for `prf_k` substantially below 256 bits;
- R2/R3 samples or public core outputs;
- unblinded/related PC opening;
- target-bound secret reuse;
- a bounded `R` candidate verifier;
- an ordinary-BASE implementation flaw affecting the fixed active ciphertext.

QP-04 (same-key R/rho coupling) is **closed as a practical route**. A full candidate `prf_k` removes `rho*H` without knowing `log_G(H)`, but testing the resulting 127-bit scalar range (and recovering `R2*R3`) still requires a generic bounded DLP of about `2^63.5` group operations; the toy models that DLP step as direct integer access.

### P4 — Continuous upstream anchor

Every new session starts with:

```text
git ls-remote origin refs/heads/main
```

Then compare tree/hash deltas before relying on any prior CLOSED verdict.

## Final verdict

```text
Target plaintext recovered?          NO
Target wallet key recovered?         NO
Target bytes changed?                NO
Public evidence changed materially?  YES — 44 R1 LPN files at d9d29d5/019380c
Does S alone decrypt?                NO under pinned source
Core blocker                         prf_k-derived R / Toeplitz / R2/R3 / rho
Most important correction            distinguish target bytes, active status,
                                     announcement snapshot, and live HEAD
```

The correct status is **NOT SOLVED, PUBLIC INPUT REOPENED, MAIN RECOVERY PATH STILL BLOCKED**.
