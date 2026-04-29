# JARDÍN - Post-Quantum Hybrid Ethereum Accounts

---

> ## WARNING: RESEARCH PROTOTYPE - NOT FOR PRODUCTION USE
>
> Hybrid ECDSA + SPHINCs- accounts built on top of plain-SPHINCS+ (SPX) and
> plain-FORS verifiers. **Not audited**, no security guarantees, do not use
> with real funds. Use on testnets only.

---

**JARDÍN** (Judicious Authentication from Random-subset Domain-separated Indexed Nodes) is a post-quantum smart-account design that combines:

1. A **stateless registration path** - one SPHINCS- signature per rotation event opens a "slot" (a sub-key commitment) on-chain.
2. A **compact path** - each subsequent transaction uses a FORS signature at constant ~60 K verify gas, against the sub-key authorised by the latest registration.

Both ERC-4337 (hybrid ECDSA + PQ, Sepolia) and EIP-8141 frame transactions (pure PQ, ethrex) are supported.

The underlying SPHINCs-/SLH-DSA verifier research - C-series, SPX, SLH-DSA-SHA2-128-24, SLH-DSA-Keccak-128-24 - lives in a separate repo: [`nconsigny/SPHINCs-`](https://github.com/nconsigny/SPHINCs-). This repo focuses on the hybrid-account wiring (Jardin accounts, factories, frame accounts, UserOp / frame-tx senders).

---

## Architecture

```
JardinSpxVerifier (plain SPHINCS+, shared)        JardinForsPlainVerifier (compact FORS+C, shared)
        ↑ verify(pkSeed, pkRoot, msg, sig)                ↑ verifyForsPlain(subSeed, subRoot, msg, sig)
        │                                                 │
        └────── Type 1 (ECDSA + SPX registers a slot) ────┘── Type 2 (ECDSA + plain-FORS against registered slot)
                                    │
                          JardinAccount (ERC-4337, hybrid)
                          ├── owner                         (ECDSA signer, rotatable)
                          ├── spxPkSeed / spxPkRoot         (SPX identity, rotatable)
                          ├── c11Verifier / c11PkSeed /
                          │   c11PkRoot                     (zero until attached via Type 3 recovery)
                          └── slots: mapping(H(subPkSeed,subPkRoot) ⇒ uint256)
```

All three verifiers share one 32-byte JARDIN ADRS layout (`layer4‖tree8‖type4‖kp4‖ci4‖cp4‖ha4`) and one keccak-based tweakable-hash kernel. See [`script/jardin_primitives.py`](./script/jardin_primitives.py) for the off-chain side.

## Variants

JARDIN combines two SPHINCs--family verifiers, each on its own lane:

- **`JardinSpxVerifier.sol`** runs the **registration / fallback** path. Plain SPHINCS+ (SLH-DSA construction) with the JARDIN 32-byte ADRS kernel and keccak256 truncated to 16 B. This is the same contract as `SPHINCs-C12Asm.sol` in [`nconsigny/SPHINCs-`](https://github.com/nconsigny/SPHINCs-). One signature per slot rotation (or per emergency fallback).
- **`JardinForsPlainVerifier.sol`** runs the **compact** path. Plain FORS with the same 32-byte ADRS kernel; few-time per registered slot (Q_MAX = 2^h signatures before the slot is exhausted). Constant verify gas regardless of `q`.

The two paths have different security models, so they're documented in separate tables: SPX is a *stateless* signature with the standard hypertree security profile (degrades with total q), plain-FORS is a *few-time* signature whose security is bounded by the slot's hard cap and characterised by reuse multiplicity γ (not by lifetime q).

### Plain SPX — stateless registration path

`h=20  d=5  a=7  k=20  w=8  l=45,  n=16,  no grinding.  Sig 6,512 B.`

| Metric | Value | Source |
|---|---|---|
| sec_10 (≤ 2¹⁰ sigs/key) | 128 bit | `compute_security` model (SPHINCs- README) |
| sec_14 (≤ 2¹⁴) | 127.8 bit | ″ (knee) |
| sec_18 (≤ 2¹⁸) | 109.1 bit | ″ |
| sec_20 (≤ 2²⁰, hard cap) | 95.4 bit | ″ |
| Verify gas (pure assembly, `gasleft()`) | 276 K | Foundry test |
| 4337 `handleOps` (Type 1: ECDSA + SPX + register slot) | **519,487** | [tx 0x6797bdcc...](https://sepolia.etherscan.io/tx/0x6797bdccff4c122c7d493e1de5725980a86c411163f26e5c07315ed44fb02c81) |
| Sign keccak count (zero-memory) | 36.6 K (modelled); 31.5 K measured, 47.3 s on Ledger Nano S+ ST33K1M5 | repo / hardware test |

The 519,487 gas Type 1 figure breaks down as: EntryPoint v0.9 baseline ~95 K + ECDSA recover ~5 K + SPX verify ~276 K + 16+16-byte slot SSTOREs ~44 K + 6,610-byte calldata ~80 K (16 gas/byte after EIP-7623 slack). Calldata dominates the cost floor because the signature is large.

### Plain FORS — compact signing path

`k=32  a=4  h ∈ [2, 7],  n=16.  Sig = 2,593 + 16·h B  (2,657 at h=4, 2,705 at h=7).`

Few-time **per slot**, so `sec_N` (lifetime-q security) doesn't apply — the slot is bounded by 2^h signatures by construction; once exhausted the device generates a fresh `r` and the SPX path registers a new slot.

| Metric | h=4 (Q=16) | h=7 (Q=128) | Notes |
|---|---|---|---|
| Slot capacity (max sigs) | 16 | 128 | hard cap; rotate to a fresh `r` |
| Sig length | 2,657 B | 2,705 B | `2593 + 16·h` |
| Verify gas (pure, est.) | ~60 K | ~60 K | k=32 trees × 5 keccak each + outer Merkle h × 1 keccak |
| 4337 `handleOps` (Type 2: ECDSA + plain-FORS compact) | **173,142** | not yet measured | h=4: [tx 0x30f6dfbf...](https://sepolia.etherscan.io/tx/0x30f6dfbf6b25fb809e97efa725106c7a5d9208861a57c6e446b48530f61c5b6c) |
| Sign keccak count | ~550 | ~550 | per signature, slot already cached |

### FORS reuse profile (security as a function of γ = single-leaf reuses)

For comparison across FORS parameter choices. γ is the number of times a single FORS instance gets re-signed (slot index hash collision under adversarial messages — anti-rollback should keep this at 1; γ=2 is the double-sign worst case if the device's burn-before-sign fails).

| Variant | γ=1 | γ=2 | γ=3 | γ=5 | γ=10 | γ=20 |
|---|---|---|---|---|---|---|
| **k=32, a=4 (this repo's plain FORS)** | 128.0 | 97.5 | 80.2 | 59.4 | 34.3 | 14.9 |
| k=26, a=5 | 130.0 | 104.6 | 90.0 | 72.0 | 48.8 | 27.5 |
| k=22, a=6 | 132.0 | 110.2 | 97.6 | 81.9 | 61.1 | 38.4 |
| k=14, a=12 (NIST FIPS 205-like) | 168.0 | 154.4 | 146.4 | 134.0 | 119.0 | 105.0 |

Bigger trees (`a` up, `k` down) keep more security under reuse but make per-slot keygen and sign cost grow exponentially in `a`; the JARDIN choice of `k=32, a=4` minimises signer / device cost at the price of steeper γ-degradation. Across the full system, slot rotation independent per `r` keeps the system-level floor at ~116 bits even if a single slot is re-used once.

The compact-path value proposition: one expensive SPX registration (~519 K 4337 gas) opens a slot of `Q_MAX = 2^h` cheap signatures at ~173 K each (h=4), then the device rotates to a fresh `r`. The SPX path is also always available as a stateless fallback when the compact slot state is lost.

## Contracts

### Active (`src/`)

| File | Purpose |
|---|---|
| `JardinSpxVerifier.sol` | Plain SPHINCS+ (SPX) verifier - h=20, d=5, a=7, k=20, w=8, l=45. 6,512-B sig, ~276 K verify |
| `JardinForsPlainVerifier.sol` | Plain-FORS compact verifier - k=32, a=4, variable outer Merkle h ∈ [2,8]. ~60 K verify |
| `JardinAccount.sol` | ERC-4337 hybrid account: Type 1 (SPX + register), Type 2 (plain-FORS), Type 3 (optional C11 recovery via `attachC11Recovery`) |
| `JardinAccountFactory.sol` | CREATE2 factory for `JardinAccount`. Wires SPX + plain-FORS as immutables |
| `JardineroFrameAccount.sol` | EIP-8141 pure-PQ frame account. Keys embedded in bytecode via PUSH32 |

### Legacy (`legacy/`)

Prior JARDIN variants, frozen for benchmark reproducibility:

- `legacy/src/JardinForsCVerifier.sol` - FORS+C compact verifier with counter-grinding
- `legacy/src/JardinT0Verifier.sol` - T0 (WOTS+C) registration-path variant
- `legacy/src/JardinFrameAccount.sol` - earlier frame-account version

## Off-chain

- `script/jardin_primitives.py` - shared primitives (keccak256, 32-byte ADRS builder, tweakable hash helpers)
- `script/jardin_spx_signer.py` - Python SPX signer (plain SPHINCS+)
- `script/jardin_fors_plain_signer.py` - Python plain-FORS compact-path signer
- `script/jardin_spx_userop.py` - ERC-4337 UserOp builder (SPX + plain-FORS via Candide bundler)
- `script/jardinero_frame_tx.py` - EIP-8141 frame-tx builder for ethrex
- `script/deploy_jardin_frame.py` - hand-optimised frame proxy deployer (`--verifier spx`/`c11` flag)
- `script/frame_tx.py` - generic frame-tx sender
- `signer-wasm/` - Rust/WASM signer with BIP-39/44 key derivation

## Build and Test

```bash
forge build
forge test
(cd signer-wasm && cargo test --release -- --ignored)
```

Python env: `pip install eth-account eth-abi requests pycryptodome`.

## Deploy

```bash
# Deploy SPX + plain-FORS verifiers + JardinAccountFactory to Sepolia:
forge script script/DeployJardineroSepolia.s.sol --rpc-url sepolia --broadcast

# Deploy a frame account (ethrex):
python3 script/deploy_jardin_frame.py --verifier spx
```

## ADRS layout (32 bytes)

```
bytes  0.. 3   layer     uint32 BE
bytes  4..11   tree      uint64 BE
bytes 12..15   type      uint32 BE   (0 WOTS_HASH, 1 WOTS_PK, 2 XMSS_TREE, 3 FORS_TREE, 4 FORS_ROOTS, 16 JARDIN_MERKLE)
bytes 16..19   kp        uint32 BE   (keypair / FORS leaf index)
bytes 20..23   ci        uint32 BE   (chain index or FORS counter)
bytes 24..27   cp        uint32 BE   (chain position or tree height)
bytes 28..31   ha        uint32 BE   (hash address or tree index)
```

Every on-chain verifier in this repo, and the Python primitives in `jardin_primitives.py`, write the ADRS in this exact order.
