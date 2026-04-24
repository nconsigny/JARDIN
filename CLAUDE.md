# CLAUDE.md

Guidance for AI coding assistants working in this repository.

## Project Overview

JARDÍN is a post-quantum hybrid smart-account stack built on top of plain-SPHINCS+ (SPX) and plain-FORS compact signatures. Supports ERC-4337 (hybrid ECDSA + PQ on Sepolia) and EIP-8141 frame transactions (pure PQ on ethrex).

Related repo: [nconsigny/SPHINCs-](https://github.com/nconsigny/SPHINCs-) — pure SPHINCS+ research (C-series, SPX, SLH-DSA-128-24 verifiers without the JARDIN account wiring).

**Not audited, not production-safe.**

## Build and Test

```bash
forge build                                             # compile all contracts
forge test                                              # run all forge tests
(cd signer-wasm && cargo test --release -- --ignored)  # Rust signer (9/9 tests)
```

Python env: `pip install eth-account eth-abi requests pycryptodome`.

## Architecture — Shared Verifier Model

Every verifier is deployed once as a stateless pure contract and shared by all accounts. Accounts store their own keys and pass them into the verifier on each call.

```
<verifier> (deployed once, stateless, pure)
    ↑ verify(pkSeed, pkRoot, message, sig) → bool
    │
    ├── JardinAccount          (ERC-4337, keys as immutables)
    └── JardineroFrameAccount  (EIP-8141, keys embedded in bytecode via PUSH32)
```

All active verifiers share one 32-byte ADRS layout and one set of tweakable-hash primitives (see `script/jardin_primitives.py`). A device port needs a single `sphincs_th*` implementation covering every path.

## Current contracts (`src/`)

| File | Purpose |
|---|---|
| `JardinSpxVerifier.sol` | Plain SPHINCS+ (SPX) registration verifier — h=20, d=5, h'=4, a=7, k=20, w=8, l=45. 6,512-B sig, 32-byte JARDIN ADRS, ~276 K verify |
| `JardinForsPlainVerifier.sol` | Plain-FORS compact-path verifier — k=32, a=4, variable outer Merkle h ∈ [2,8] (inferred from sig length). ~60 K verify |
| `JardinAccount.sol` | ERC-4337 hybrid. Type 1 (SPX + register), Type 2 (plain-FORS against registered slot), Type 3 (C11 optional recovery after `attachC11Recovery`) |
| `JardinAccountFactory.sol` | CREATE2 factory wiring SPX + plain-FORS as immutables on each account |
| `JardineroFrameAccount.sol` | EIP-8141 pure-PQ frame account — keys live in bytecode (no SLOAD) |

## Signature types

**Type 1 (SPX registration path)** — any message:
```
[0x01][ecdsaSig 65][subPkSeed 16][subPkRoot 16][SPX sig 6,512]  ≈ 6,610 B
```
If `subPkSeed == subPkRoot == 0`, registration is skipped (stateless fallback).

**Type 2 (plain-FORS compact)** — requires a registered slot:
```
[0x02][ecdsaSig 65][subPkSeed 16][subPkRoot 16][R 16][FORS body 2,560][q 1][merkleAuth h×16]
sig-length = 2,657 B at h=4 up to 2,721 B at h=8
```

**Type 3 (C11 recovery, optional)** — only after calling `attachC11Recovery()` from the account itself. Needs C11 verifier at an external address; keys are stored in the account.

Domain separators in H_msg (trailing 32-byte word): SPX `0xFF..FC`, plain-FORS `0xFF..FD`, T0 `0xFF..FE`, C11 `0xFF..FF`.

## Off-chain (`script/`)

Shared primitives:
- `jardin_primitives.py` — keccak256, `make_adrs` (32-byte), `th` / `th_pair` / `th_multi`, ADRS type constants, HMAC-SHA-512 helpers

Signers:
- `jardin_spx_signer.py` — plain SPHINCS+
- `jardin_fors_plain_signer.py` — plain-FORS compact (variable h)

UserOp / frame-tx builders:
- `jardin_spx_userop.py` — ERC-4337 UserOp with Candide bundler
- `jardinero_frame_tx.py` — EIP-8141 frame-tx builder (ethrex)
- `frame_tx.py` — generic frame-tx sender
- `deploy_jardin_frame.py` — hand-optimised proxy deployer (`--verifier {spx,c11}`)

Deploy:
- `script/DeployJardineroSepolia.s.sol` — SPX + plain-FORS + factory

Legacy signers under `legacy/script/` target frozen variants (T0, FORS+C with counter-grinding, old frame-tx senders).

## Key derivation

```
BIP-39 mnemonic (24 words)
    ├── HMAC-SHA-512("sphincs-c11-v1", seed) → master SPX/FORS key material (quantum-safe)
    └── BIP-32 m/44'/60'/0'/0/0              → ECDSA address (independent)
```

The two paths are independent — compromising either doesn't compromise the other.

## Gas Optimizations

- Branchless Merkle swap: `mstore(xor(0x40, s), node)` (Solady pattern) — works because L/R live at 32-byte-aligned slots 0x40 and 0x60.
- SHL for power-of-2 multiplications: `shl(4, i)` instead of `mul(i, 16)`
- Hoisted loop-invariant chain ADRS: `chainBase` computed once per WOTS chain
- Domain-separated H_msg: 160-byte hash prevents cross-variant `th_pair` collisions
- Frame-account v2: keys embedded as PUSH32 (no SLOAD, saves ~4.2 K gas)

## Foundry Config

- `via_ir = true`, `optimizer_runs = 200`
- `ffi = true` (for Python signer calls from Forge tests)
- Sepolia (chain 11155111), ethrex (chain 1729)
