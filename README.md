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
- **`JardinForsPlainVerifier.sol`** runs the **compact** path. Plain FORS with the same 32-byte ADRS kernel; few-time security per registered slot (Q_MAX = 2^h_outer signatures before the slot is exhausted). Constant verify gas regardless of `q`.

| Verifier | Family | role | h | d | a | k | w | l | Sig | sign_h | Verify | Frame | 4337 (Type 1 / Type 2) | sec |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **JardinSpxVerifier** | plain SPHINCS+ / SLH-DSA | registration / fallback | 20 | 5 | 7 | 20 | 8 | 45 | 6,512 B | ~36.6 K keccak | ~276 – 278 K (compute); ~401 K on-chain (calldata floor 64 × 6,512 = 416,768 dominates) | - | **416 K** (Type 1: ECDSA + SPX + register, measured) | 128-bit at q ≤ 2¹¹; 127.8 at 2¹⁴ knee; flat through 2¹⁴; hypertree cap 2²⁰ |
| **JardinForsPlainVerifier** | plain FORS (few-time) | compact tx | 2..8† | - | 4 | 32 | - | - | 2,625 B (h=2) … 2,657 B (h=4) … 2,721 B (h=8) — `2593 + 16·h` | per-slot keygen `2^h × ~k·2^(a+1) ≈ 2^h × 1,024` keccak (~16 K @ h=4 … ~262 K @ h=8); per-sig ≪1 K from a cached slot | **~60 K constant** (no WOTS chains; reveal climb is k·a + h = 128 + h H-calls) | ~95 K projected (~60 K verify + frame overhead) — not yet measured for plain-FORS | TBD — not yet measured for plain-FORS | k·a = 128-bit one-time; graceful: 105-bit at r=2 (double-sign), 74-bit at r=5; Q_MAX = 2^h per slot |

† `h` is chosen per slot by the signer and is inferred at verify time from the signature length: `h = (sig.length − 2593) / 16` (revert unless `2 ≤ h ≤ 8` and `(sig.length − 2593) % 16 == 0`).

- **Family**: `plain SPHINCS+ / SLH-DSA` is the standard FIPS 205 construction (no counter-grinding), instantiated here with keccak256 + JARDIN 32-byte ADRS instead of FIPS 205's SHA-256 + 22-byte compressed ADRSc. `plain FORS (few-time)` is the FORS sub-tree from SPHINCS+ used standalone as a few-time signature scheme; each slot is a balanced Merkle tree of 2^h independent FORS public keys, registered on-chain by one SPX signature.
- **sign_h**: keccak calls per signing event. SPX is constant-cost per sig (cold signer; with a cached top-level XMSS tree it would drop to <1 K per sig). plain-FORS is dominated by per-slot keygen and then amortised over Q_MAX = 2^h compact signatures from the slot.
- **Verify**: pure verifier compute (Foundry `gasleft()`). For SPX the on-chain tx cost is bounded below by the calldata floor of the 6,512-byte signature: `64 × 6,512 = 416,768` gas (or 16 × 6,512 = 104,192 with all-nonzero / EIP-7623 floor, whichever applies). For plain-FORS verify is essentially constant per `h` because the reveal climb is `k·a + h = 128 + h` H-calls regardless of which leaf in the slot is opened.
- **Frame / 4337**: total tx gas (ethrex EIP-8141 / Sepolia ERC-4337 with `JardinAccount` + EntryPoint v0.9). **The Type 1 (SPX register) 4337 number is measured at 416 K. The Type 2 (plain-FORS compact) numbers are *not yet measured* against the current plain-FORS verifier — the 119 K / 176 K numbers in earlier drafts of this doc were FORS+C measurements and have been removed.**

The compact lane is the value proposition: one expensive SPX registration (~416 K 4337 gas) opens a slot of `Q_MAX = 2^h` cheap signatures, then every subsequent in-slot tx pays only the plain-FORS verify (~60 K compute). A wallet rotating slots every 128 txs pays the SPX price < 1 % of the time. The SPX path is also always available as a stateless fallback when the compact slot state is lost.

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
