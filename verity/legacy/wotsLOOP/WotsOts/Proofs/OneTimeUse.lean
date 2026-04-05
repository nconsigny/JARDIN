/-
  Proofs/OneTimeUse.lean — One-time use invariant.

  Proves that:
  1. After verifyAndMark succeeds, the leaf is marked as used.
  2. A used leaf cannot be verified again (no double use).

  These two properties together guarantee that each WOTS+C key is used at most once,
  which is the critical security requirement for one-time signature schemes.
-/

import WotsOts.Types
import WotsOts.Bitmap
import WotsOts.Contract
import WotsOts.Spec

namespace WotsOts.Proofs.OneTimeUse

open WotsOts WotsOts.Bitmap WotsOts.Contract WotsOts.Spec

-- ════════════════════════════════════════════════════════════
--  THEOREM 1: Successful verification marks the leaf
-- ════════════════════════════════════════════════════════════

theorem verifyAndMark_marks_leaf (s : ContractState) (msg : Nat) (sig : OtsSig) :
    marksLeafOnSuccess s msg sig := by
  intro leafIdx s' h_success
  simp [verifyAndMark] at h_success
  obtain ⟨h_bound, h_unused, h_valid, h_state⟩ := h_success
  rw [← h_state]
  simp [Bitmap.isUsed, Bitmap.mark]
  exact Bitmap.mark_sets s.usedBitmap sig.leafIdx h_bound

-- ════════════════════════════════════════════════════════════
--  THEOREM 2: Used leaves cannot be re-verified
-- ════════════════════════════════════════════════════════════

theorem verifyAndMark_rejects_used (s : ContractState) (msg : Nat) (sig : OtsSig) :
    noDoubleUse s msg sig := by
  intro h_used
  simp [verifyAndMark]
  -- The guard (isUsed == false) fails when the leaf is already used
  intro h_bound
  simp [h_used]

-- ════════════════════════════════════════════════════════════
--  COROLLARY: A leaf verified once cannot be verified again
-- ════════════════════════════════════════════════════════════

/-- After a successful verifyAndMark, the same leaf cannot be used in the resulting state -/
theorem once_used_stays_blocked (s : ContractState) (msg1 msg2 : Nat)
    (sig1 sig2 : OtsSig) (leafIdx : Nat) (s' : ContractState)
    (h_first : verifyAndMark s msg1 sig1 = some (leafIdx, s'))
    (h_same_leaf : sig2.leafIdx = leafIdx) :
    verifyAndMark s' msg2 sig2 = none := by
  have h_marked := verifyAndMark_marks_leaf s msg1 sig1 leafIdx s' h_first
  rw [h_same_leaf] at *
  exact verifyAndMark_rejects_used s' msg2 sig2 h_marked

-- ════════════════════════════════════════════════════════════
--  THEOREM: leafIdx in output matches sig.leafIdx
-- ════════════════════════════════════════════════════════════

theorem verifyAndMark_returns_sig_leaf (s : ContractState) (msg : Nat) (sig : OtsSig)
    (leafIdx : Nat) (s' : ContractState)
    (h : verifyAndMark s msg sig = some (leafIdx, s')) :
    leafIdx = sig.leafIdx := by
  simp [verifyAndMark] at h
  obtain ⟨_, _, _, h_eq⟩ := h
  -- leafIdx comes from the return value which is sig.leafIdx
  sorry -- Depends on exact Option.bind unfolding

end WotsOts.Proofs.OneTimeUse
