/-
  WotsOts/Spec.lean — Formal specifications for the WOTS+C OTS contract.

  Defines the key safety and correctness properties that the contract must satisfy.
  Each spec is a Prop predicate over contract states and transitions.
  The proofs are in the Proofs/ directory.

  Following the Morpho-Verity pattern: specs are stated independently,
  then proven against the functional model, then transferred to Solidity via bridge.
-/

import WotsOts.Types
import WotsOts.Bitmap
import WotsOts.Contract

namespace WotsOts.Spec

open WotsOts WotsOts.Contract

-- ════════════════════════════════════════════════════════════
--  INVARIANT 1: Bitmap Monotonicity
--  Once a leaf is marked as used, it remains used forever.
-- ════════════════════════════════════════════════════════════

/-- Every state transition preserves used leaf status -/
def bitmapMonotone (s s' : ContractState) : Prop :=
  ∀ idx : Nat, idx < maxKeys →
    Bitmap.isUsed s.usedBitmap idx = true →
    Bitmap.isUsed s'.usedBitmap idx = true

-- ════════════════════════════════════════════════════════════
--  INVARIANT 2: One-Time Use
--  After verifyAndMark succeeds, the used leaf is marked.
-- ════════════════════════════════════════════════════════════

/-- Successful verification marks the leaf as used -/
def marksLeafOnSuccess (s : ContractState) (msg : Nat) (sig : OtsSig) : Prop :=
  ∀ leafIdx s',
    verifyAndMark s msg sig = some (leafIdx, s') →
    Bitmap.isUsed s'.usedBitmap leafIdx = true

-- ════════════════════════════════════════════════════════════
--  INVARIANT 3: No Double Use
--  If a leaf is already used, verifyAndMark reverts.
-- ════════════════════════════════════════════════════════════

/-- Used leaves cannot be re-verified -/
def noDoubleUse (s : ContractState) (msg : Nat) (sig : OtsSig) : Prop :=
  Bitmap.isUsed s.usedBitmap sig.leafIdx = true →
  verifyAndMark s msg sig = none

-- ════════════════════════════════════════════════════════════
--  INVARIANT 4: Nonce Monotonicity
--  Execute always increments the nonce by exactly 1.
-- ════════════════════════════════════════════════════════════

/-- Successful execution increments nonce -/
def nonceIncrementsOnExecute (s : ContractState) (tx : TxParams)
    (sig : OtsSig) (addr : Nat) : Prop :=
  ∀ s', execute s tx sig addr = some s' → s'.nonce = s.nonce + 1

-- ════════════════════════════════════════════════════════════
--  INVARIANT 5: Key Exhaustion
--  When all 1024 keys are consumed, no more signatures can verify.
-- ════════════════════════════════════════════════════════════

/-- Full bitmap means all verifications fail -/
def exhaustionBlocks (s : ContractState) : Prop :=
  (∀ idx : Nat, idx < maxKeys → Bitmap.isUsed s.usedBitmap idx = true) →
  ∀ msg sig, verifyAndMark s msg sig = none

-- ════════════════════════════════════════════════════════════
--  INVARIANT 6: Immutability of Cryptographic Parameters
--  pkSeed and merkleRoot never change across any transition.
-- ════════════════════════════════════════════════════════════

/-- Execute preserves cryptographic parameters -/
def paramsImmutable (s : ContractState) (tx : TxParams)
    (sig : OtsSig) (addr : Nat) : Prop :=
  ∀ s', execute s tx sig addr = some s' →
    s'.pkSeed = s.pkSeed ∧ s'.merkleRoot = s.merkleRoot

end WotsOts.Spec
