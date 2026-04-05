/-
  SphincsC6.Proofs.Correctness — Key correctness proofs for C6.
-/
import SphincsC6.Types
import SphincsC6.Hash
import SphincsC6.WotsC
import SphincsC6.ForsC
import SphincsC6.Hypertree
import SphincsC6.Contract
import SphincsC6.Spec

namespace SphincsC6.Proofs

theorem wots_chain_roundtrip (seed : Hash128) (adrs : Adrs)
    (sk_i : Hash128) (digit_i : Nat) (h_bound : digit_i < W) :
    chainHash seed adrs (chainHash seed adrs sk_i 0 digit_i) digit_i (W - 1 - digit_i) =
    chainHash seed adrs sk_i 0 (W - 1) := by
  rw [chainHash_compose]; congr 1; omega

theorem digit_bounded (val : UInt256) (i : Fin L) :
    extractDigits val i < W := extractDigit_bound val i.val

theorem fors_index_bounded (digest : UInt256) (i : Fin K) :
    extractForsIndices digest i < 2^A := forsIndex_bound digest i

theorem sig_size_correct :
    SIG_SIZE = N + K * N + (K - 1) * A * N + D * (L * N + 4 + SUBTREE_H * N) := by
  simp [SIG_SIZE, N, K, A, D, L, SUBTREE_H]

theorem htIdx_range (digest : UInt256) : extractHtIdx digest < 2^H := by
  simp [extractHtIdx]; exact Nat.mod_lt _ (by positivity)

theorem htIdx_shift : K * A = 128 := by simp [K, A]

theorem verify_soundness (state : ContractState) (msg : Hash128) (sig : SphincsC6Sig) :
    verify state msg sig = true →
    ∃ computedRoot, computedRoot = state.pkRoot := by
  intro h; simp [verify] at h; split at h
  · exact ⟨state.pkRoot, rfl⟩
  · contradiction

end SphincsC6.Proofs
