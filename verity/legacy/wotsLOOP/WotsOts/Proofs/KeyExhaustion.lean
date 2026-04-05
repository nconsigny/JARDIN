/-
  Proofs/KeyExhaustion.lean — Key exhaustion invariant.

  Proves that when all 1024 WOTS+C keys have been consumed,
  no further signatures can be verified. This is the ultimate
  safety bound of the one-time signature scheme.
-/

import WotsOts.Types
import WotsOts.Bitmap
import WotsOts.Contract
import WotsOts.Spec

namespace WotsOts.Proofs.KeyExhaustion

open WotsOts WotsOts.Bitmap WotsOts.Contract WotsOts.Spec

-- ════════════════════════════════════════════════════════════
--  THEOREM: Full bitmap blocks all verifications
-- ════════════════════════════════════════════════════════════

theorem exhaustion_blocks_all (s : ContractState) :
    exhaustionBlocks s := by
  intro h_all_used msg sig
  simp [verifyAndMark]
  -- Case 1: leafIdx out of bounds → guard fails
  by_cases h_bound : sig.leafIdx < maxKeys
  · -- Case 2: leafIdx in bounds but used → bitmap guard fails
    have h_used := h_all_used sig.leafIdx h_bound
    simp [h_bound, h_used]
  · simp [h_bound]

-- ════════════════════════════════════════════════════════════
--  COROLLARY: At most 1024 successful verifications
-- ════════════════════════════════════════════════════════════

/-- The nonce is bounded by the number of available keys.
    After 1024 executions, no more are possible. -/
theorem nonce_bounded_by_keys (s : ContractState)
    (h_init_nonce : s.nonce ≤ maxKeys)
    (h_all_used : ∀ idx, idx < maxKeys → Bitmap.isUsed s.usedBitmap idx = true) :
    ∀ tx sig addr, execute s tx sig addr = none := by
  intro tx sig addr
  simp [execute]
  -- verifyAndMark fails because all leaves are used
  have h_exhaust := exhaustion_blocks_all s h_all_used
    (computeTxHash tx.chainId addr s.nonce tx.dest tx.value tx.dataHash) sig
  simp [h_exhaust]

end WotsOts.Proofs.KeyExhaustion
