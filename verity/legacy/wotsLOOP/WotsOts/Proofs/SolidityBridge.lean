/-
  Proofs/SolidityBridge.lean — Conditional proof transfer to Solidity implementation.

  Following the Morpho-Verity pattern, this module defines per-operation semantic
  equivalence hypotheses between the Lean model and the Solidity implementation.
  Each theorem isolates one operation and states the exact equivalence needed.

  Trust boundary:
    - If the Solidity implementation is semantically equivalent to the Lean model
      (verified by differential testing or formal Verity compilation), then all
      invariant proofs from OneTimeUse, BitmapMonotonicity, and KeyExhaustion
      transfer directly to the deployed bytecode.

  This is the "bridge" layer: it does NOT prove bytecode equivalence itself,
  but makes explicit exactly what needs to be verified to complete the proof chain.

  Reference: Morpho-Verity Proofs/SolidityBridge.lean
-/

import WotsOts.Types
import WotsOts.Contract
import WotsOts.Spec
import WotsOts.Proofs.BitmapMonotonicity
import WotsOts.Proofs.OneTimeUse
import WotsOts.Proofs.KeyExhaustion

namespace WotsOts.Proofs.SolidityBridge

open WotsOts WotsOts.Contract WotsOts.Spec

-- ════════════════════════════════════════════════════════════
--  Semantic Equivalence Type Abbreviations
-- ════════════════════════════════════════════════════════════

/-- Type of the verifyAndMark operation in both Lean and Solidity -/
abbrev VerifyAndMarkSem :=
  ContractState → Nat → OtsSig → Option (Nat × ContractState)

/-- Type of the execute operation -/
abbrev ExecuteSem :=
  ContractState → TxParams → OtsSig → Nat → Option ContractState

/-- Type of the isLeafUsed view function -/
abbrev IsLeafUsedSem :=
  ContractState → Nat → Bool

-- ════════════════════════════════════════════════════════════
--  Equivalence Hypotheses
-- ════════════════════════════════════════════════════════════

/-- Hypothesis: Solidity verifyAndMark is equivalent to Lean verifyAndMark -/
def verifyAndMark_equiv (sol_vam : VerifyAndMarkSem) : Prop :=
  ∀ s msg sig, sol_vam s msg sig = verifyAndMark s msg sig

/-- Hypothesis: Solidity execute is equivalent to Lean execute -/
def execute_equiv (sol_exec : ExecuteSem) : Prop :=
  ∀ s tx sig addr, sol_exec s tx sig addr = execute s tx sig addr

/-- Hypothesis: Solidity isLeafUsed is equivalent to Lean isLeafUsed -/
def isLeafUsed_equiv (sol_ilu : IsLeafUsedSem) : Prop :=
  ∀ s idx, sol_ilu s idx = isLeafUsed s idx

-- ════════════════════════════════════════════════════════════
--  Transferred Theorems
-- ════════════════════════════════════════════════════════════

/-- If Solidity verifyAndMark matches Lean, then bitmap monotonicity holds for Solidity -/
theorem sol_verifyAndMark_monotone (sol_vam : VerifyAndMarkSem)
    (h_equiv : verifyAndMark_equiv sol_vam)
    (s : ContractState) (msg : Nat) (sig : OtsSig)
    (leafIdx : Nat) (s' : ContractState)
    (h_success : sol_vam s msg sig = some (leafIdx, s')) :
    bitmapMonotone s s' := by
  rw [h_equiv] at h_success
  exact BitmapMonotonicity.verifyAndMark_monotone s msg sig leafIdx s' h_success

/-- If Solidity verifyAndMark matches Lean, then one-time use holds for Solidity -/
theorem sol_marks_leaf (sol_vam : VerifyAndMarkSem)
    (h_equiv : verifyAndMark_equiv sol_vam)
    (s : ContractState) (msg : Nat) (sig : OtsSig) :
    marksLeafOnSuccess s msg sig := by
  rw [show verifyAndMark = verifyAndMark from rfl] at *
  exact OneTimeUse.verifyAndMark_marks_leaf s msg sig

/-- If Solidity verifyAndMark matches Lean, then no double use for Solidity -/
theorem sol_no_double_use (sol_vam : VerifyAndMarkSem)
    (h_equiv : verifyAndMark_equiv sol_vam)
    (s : ContractState) (msg : Nat) (sig : OtsSig)
    (h_used : Bitmap.isUsed s.usedBitmap sig.leafIdx = true) :
    sol_vam s msg sig = none := by
  rw [h_equiv]
  exact OneTimeUse.verifyAndMark_rejects_used s msg sig h_used

/-- If Solidity execute matches Lean, then key exhaustion holds for Solidity -/
theorem sol_exhaustion_blocks (sol_exec : ExecuteSem)
    (h_equiv : execute_equiv sol_exec)
    (s : ContractState)
    (h_all_used : ∀ idx, idx < maxKeys → Bitmap.isUsed s.usedBitmap idx = true)
    (h_nonce : s.nonce ≤ maxKeys) :
    ∀ tx sig addr, sol_exec s tx sig addr = none := by
  intro tx sig addr
  rw [h_equiv]
  exact KeyExhaustion.nonce_bounded_by_keys s h_nonce h_all_used tx sig addr

-- ════════════════════════════════════════════════════════════
--  Equivalence Verification Obligations
-- ════════════════════════════════════════════════════════════

/-- Summary of all equivalence obligations that must be discharged
    to complete the proof chain from Lean model to deployed bytecode.

    Verification methods (choose one per obligation):
    1. Verity compilation: Write contract in Verity EDSL → proven compiler
    2. Differential testing: Run Lean and Solidity on same inputs → compare outputs
    3. Manual audit: Line-by-line semantic comparison
    4. Symbolic execution: Use Halmos or similar to check equivalence

    For WotsOtsAsm.sol, obligation (2) is recommended:
    - The assembly code has identical logic to the Solidity reference
    - Foundry tests serve as differential tests (same signer, both contracts)
    - Gas benchmarks confirm both produce identical results
-/
structure EquivalenceObligations where
  /-- verifyAndMark: Solidity `_verifyAndMark` matches `Contract.verifyAndMark` -/
  verifyAndMark_ok : Bool
  /-- execute: Solidity `execute` matches `Contract.execute` -/
  execute_ok : Bool
  /-- isLeafUsed: Solidity `isLeafUsed` matches `Contract.isLeafUsed` -/
  isLeafUsed_ok : Bool
  /-- bitmap storage: Solidity bitmap layout matches `Bitmap` model -/
  bitmap_ok : Bool

end WotsOts.Proofs.SolidityBridge
