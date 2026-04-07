# Verity Kernel for SPHINCS-

This directory contains a small Verity-compiled acceptance kernel for SPHINCS-style Merkle witnesses.

It proves that the deployed EVM bytecode accepts exactly the witnesses accepted by the Lean model.

It does not prove SPHINCS cryptographic security, nor the full production C6 verifier.

## What users should know

The verified artifact is [`SphincsKernel/`](./SphincsKernel/).

It stores one expected root and exposes two read-only acceptance APIs:

- `verifyPath`: takes a fully decoded witness with 4 explicit direction booleans.
- `verifyPackedPath`: takes the same witness with the directions packed into the low 4 bits of one word.

The headline guarantees are simple:

- `previewPath` and `previewPackedPath` reconstruct exactly the root defined by the Lean model.
- `verifyPath` returns `true` if and only if the reconstructed root equals the stored root.
- `verifyPackedPath` returns `true` if and only if the decoded packed witness reconstructs the stored root.
- Both verification entrypoints preserve storage.
- The contract is compiled with `--deny-local-obligations` and `--deny-axiomatized-primitives`.

For users evaluating the trust boundary, the important point is this:

- Lean proves the acceptance rule.
- Verity proves the compiled EVM contract implements that rule.
- This kernel does not claim that the toy `compress` function is cryptographically secure.

## File map

- `SphincsKernel/Model.lean`: typed witness model, packed witness decoding, and acceptance rule.
- `SphincsKernel/MerkleKernel.lean`: Verity contract that calls the shared Lean model directly.
- `SphincsKernel/Spec.lean`: exact function-level specs.
- `SphincsKernel/Proofs/Correctness.lean`: user-facing theorems such as acceptance iff reconstructed root matches storage.
- `SphincsKernel/Examples.lean`: named examples for a concrete witness.

## Main properties

The core statements are:

- A witness is accepted exactly when it reconstructs the configured root.
- A packed witness is accepted exactly when its decoded witness reconstructs the configured root.
- Verification is read-only.
- If you configure the contract with the root reconstructed from a witness, that witness will verify.

That is the right scale of claim for Verity today: small, inspectable, replayable, and strong.

## What is not proved

- The full `SphincsC6/` verifier is not claimed here as an end-to-end Verity proof.
- The arithmetic `compress` function is a stand-in for a hash compression primitive.
- The repo does not claim post-quantum security from this kernel alone.

What this kernel buys you is a clean verified boundary for on-chain acceptance logic.

## Build and strict checks

```bash
cd verity
lake update
lake build

# Strict Verity compilation of the recommended kernel
lake exe verity-compiler \
  --module SphincsKernel.MerkleKernel \
  --deny-local-obligations \
  --deny-axiomatized-primitives \
  --output artifacts/sphincs-kernel
```

## EVM replay tests

The Yul artifact is not just generated; it is exercised directly in Foundry.

```bash
# From the repo root
forge test --match-contract MerkleKernelVerityTest -vv
```

That test:

- recompiles `verity/artifacts/sphincs-kernel/MerkleKernel.yul` into deployable bytecode,
- deploys the raw Verity artifact,
- checks named example vectors for both explicit and packed witnesses,
- fuzzes `previewPath` against a tiny Solidity reference model,
- fuzzes `previewPackedPath` against a reference packed-decoding model,
- fuzzes `verifyPath` to show acceptance iff `candidateRoot == storedRoot`,
- fuzzes `verifyPackedPath` to show acceptance iff the decoded witness matches the stored root,
- checks that verification preserves storage.

## Why this is useful for SPHINCS-

For a real SPHINCS deployment, this suggests the better split:

1. Keep the heavy cryptographic logic as a pure reference model and test oracle.
2. Encode the on-chain acceptance boundary as a small typed witness.
3. Verify that boundary end-to-end with Verity.
4. State the guarantees at that boundary, not beyond it.

That gives users something they can actually reason about: what exact witness shape is accepted on-chain, and what exact property the contract enforces.
