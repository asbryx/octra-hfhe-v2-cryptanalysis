# Public Chain and Funding Provenance

## Result

The active v2 reward was funded with value recycled from the canceled v1 challenge wallet. This establishes common operational provenance, but the public HFHE artifacts show no key, nonce, tag, or commitment fingerprint reuse between v1 and active v2.

## Exact fund flow

| UTC | Transaction | From | To | OCT |
|---|---|---|---|---:|
| 2026-07-07 10:30:12 | `26b5bb1e0c819761531630084075b51db13cf5854b6e7af6551af688169cb1f1` | canceled-v1 wallet `oct6Y7...9Zn` | one-use relay `oct9jb...cBW` | 499,999.900000 |
| 2026-07-07 11:26:53 | `36daec2744d0be4695d084c73577866f688861ad8f0d766327b5bfd5f795e15a` | relay | organizer/funder `oct7xC...cGb` | 499,999.870000 |
| 2026-07-09 20:52:07 | `ad1af0cf96a12105bb112b0f3f7275e8fbd713e2f6966d886f5ec2c04e514898` | organizer/funder | active-v2 target `octC5e...uAZ` | 500,000 |

Both the canceled-v1 wallet and the relay used account nonce 1 for their outgoing transfer. The relay has only two confirmed history entries and ends at zero balance.

This is value provenance only. It does not imply wallet-key reuse, HFHE-secret reuse, or related randomness.

## Direct v1-to-v2 HFHE reuse gate

A historical parser was built from the exact v1 serializer at challenge commit `900255d` and PVAC commit `e2835df`. The existing active-v2 probe was rerun at target-introduction commit `88a72b7` and PVAC commit `071b0e9`.

```text
v1:        canon=3146670502307571117
           H_digest=401223228d9b43f3f1ba3fcceb376805ed771327db1718657615d525b30ca8ff
           8 BASE layers, 8 unique nonces/tags/PC points

active v2: canon=531565633433868593
           H_digest=601435f4977dd2a0c396bd96c7947fb884b602a52b6d7e0660b3fce3508497f5
           44 BASE layers, 44 unique nonces/tags/PC points

nonce intersection = 0
ztag intersection  = 0
PC intersection    = 0
```

The distinct public-key fingerprint and empty layer intersections close the cheap cross-version reuse route. This does not prove independent entropy internally, but there is no public fingerprint of reused HFHE key state.

## Target-adjacent transactions

The target acquired three post-funding interactions from unrelated users:

- one successful `unlock_trusted` call credited 1 OCT through a bridge program owned and operated by the caller;
- two successful transfers credited 2,000,000 units of the plain token `Penguplush`;
- the token sender later transferred 1 OCT directly.

The bridge program was deployed on July 8 by its caller. The token was initialized on May 7 and has hundreds of unrelated transfers. Neither program stores or exposes target private-key material, an HFHE secret, or a challenge verifier.

## Circle discovery closure

The mainnet scan covered 3,300 recent transactions from July 1 onward, including 2,583 Circle operations and five Circle IDs. Full public transaction histories were then scanned for the two database-like Circles:

- sealed SQLite mirror: 1,673 transactions;
- public fact ledger: 1,598 transactions.

No target address, active artifact hash, challenge label, `secret.ct`, `prf_k`, or `lpn_s_bits` marker appeared. The sealed database's plaintext write history identifies it as an Octra Vitals accounting/bridge mirror, not challenge infrastructure. Sealed state was not accessed or bypassed.

## Reopen condition

Reopen this path only for a target-bound producer log, generation binary, wallet seed relation, repeated HFHE fingerprint, or another artifact tied to the active `pk.bin`/`secret.ct` pair.

Machine-readable evidence is in `results/public_chain_provenance.json`.
