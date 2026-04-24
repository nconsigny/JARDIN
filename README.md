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
