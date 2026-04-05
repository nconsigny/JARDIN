/-
  Proofs/BitmapMonotonicity.lean — Bitmap monotonicity invariant.

  Proves that every state transition in the WotsOts contract preserves the
  bitmap monotonicity property: once a leaf is marked, it stays marked.

  This is the foundational invariant from which one-time use safety derives.
-/

import WotsOts.Types
import WotsOts.Bitmap
import WotsOts.Contract
import WotsOts.Spec

namespace WotsOts.Proofs.BitmapMonotonicity

open WotsOts WotsOts.Bitmap WotsOts.Contract WotsOts.Spec

-- ════════════════════════════════════════════════════════════
--  THEOREM: verifyAndMark preserves bitmap monotonicity
-- ════════════════════════════════════════════════════════════

theorem verifyAndMark_monotone (s : ContractState) (msg : Nat) (sig : OtsSig)
    (leafIdx : Nat) (s' : ContractState)
    (h_success : verifyAndMark s msg sig = some (leafIdx, s')) :
    bitmapMonotone s s' := by
  intro idx h_lt h_used
  simp [verifyAndMark] at h_success
  obtain ⟨h_bound, h_unused, h_valid, h_state⟩ := h_success
  rw [← h_state]
  exact Bitmap.mark_monotone s.usedBitmap sig.leafIdx idx h_lt h_used

-- ════════════════════════════════════════════════════════════
--  THEOREM: execute preserves bitmap monotonicity
-- ════════════════════════════════════════════════════════════

theorem execute_monotone (s : ContractState) (tx : TxParams)
    (sig : OtsSig) (addr : Nat) (s' : ContractState)
    (h_success : execute s tx sig addr = some s') :
    bitmapMonotone s s' := by
  simp [execute] at h_success
  obtain ⟨_, s_mid, h_vam, h_nonce⟩ := h_success
  intro idx h_lt h_used
  rw [← h_nonce]
  simp [bitmapMonotone]
  have h_mono := verifyAndMark_monotone s
    (computeTxHash tx.chainId addr s.nonce tx.dest tx.value tx.dataHash)
    sig _ s_mid h_vam
  exact h_mono idx h_lt h_used

-- ════════════════════════════════════════════════════════════
--  COROLLARY: Transitive monotonicity (for sequences of txs)
-- ════════════════════════════════════════════════════════════

/-- Bitmap monotonicity is transitive -/
theorem monotone_trans (s1 s2 s3 : ContractState)
    (h12 : bitmapMonotone s1 s2) (h23 : bitmapMonotone s2 s3) :
    bitmapMonotone s1 s3 := by
  intro idx h_lt h_used
  exact h23 idx h_lt (h12 idx h_lt h_used)

end WotsOts.Proofs.BitmapMonotonicity
