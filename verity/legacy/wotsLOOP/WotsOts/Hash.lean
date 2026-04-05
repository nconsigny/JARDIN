/-
  WotsOts/Hash.lean — Abstract hash function model.

  We model the tweakable hash function abstractly as an opaque function.
  The security properties of WOTS+C derive from collision resistance and
  second-preimage resistance of the underlying hash — we state these as axioms.
  This matches the standard cryptographic game-based approach.

  In a full Verity proof, these would be discharged by the bytecode equivalence
  layer. Here they serve as the trust boundary (cf. Morpho-Verity SolidityBridge).
-/

namespace WotsOts.Hash

open WotsOts

/-- Abstract tweakable hash function: Th(seed, adrs, input) → 128-bit output.
    Models keccak256(seed || adrs || input) & N_MASK from TweakableHash.sol. -/
opaque th (seed : Nat) (adrs : Types.Adrs) (input : Nat) : Nat

/-- Two-input tweakable hash: Th(seed, adrs, left, right) → 128-bit output.
    Used for Merkle tree internal nodes. -/
opaque thPair (seed : Nat) (adrs : Types.Adrs) (left right : Nat) : Nat

/-- Multi-input tweakable hash: Th(seed, adrs, inputs[]) → 128-bit output.
    Used for WOTS+C public key compression. -/
opaque thMulti (seed : Nat) (adrs : Types.Adrs) (inputs : List Nat) : Nat

/-- Message hash: H_msg(seed, adrs, msg, count) → 256-bit digest.
    Used for WOTS+C digest computation. -/
opaque hMsg (seed : Nat) (adrs : Types.Adrs) (msg : Nat) (count : Nat) : Nat

-- ════════════════════════════════════════════════════════════
--  Cryptographic Assumptions (axiomatized)
-- ════════════════════════════════════════════════════════════

/-- Collision resistance: different inputs produce different outputs.
    This is the core assumption underlying WOTS+C security. -/
axiom th_collision_resistant :
  ∀ seed adrs x y, th seed adrs x = th seed adrs y → x = y

/-- Domain separation: different ADRS tweaks produce independent outputs.
    This prevents multi-target attacks across different chain positions. -/
axiom th_domain_separated :
  ∀ seed adrs1 adrs2 x, adrs1 ≠ adrs2 → th seed adrs1 x ≠ th seed adrs2 x

-- ════════════════════════════════════════════════════════════
--  Chain Hash (iterated tweakable hash)
-- ════════════════════════════════════════════════════════════

/-- Construct ADRS with specific chain position -/
def withChainPos (adrs : Types.Adrs) (pos : Nat) : Types.Adrs :=
  { adrs with chainPos := pos }

/-- Chain hash: iterate th for `steps` applications starting at position `startPos`.
    Models TweakableHash.chainHash from the Solidity contract. -/
def chainHash (seed : Nat) (adrs : Types.Adrs) (val : Nat) (startPos steps : Nat) : Nat :=
  match steps with
  | 0 => val
  | n + 1 =>
    let nextVal := th seed (withChainPos adrs startPos) val
    chainHash seed adrs nextVal (startPos + 1) n

/-- Chain hash of 0 steps is identity -/
@[simp]
theorem chainHash_zero (seed : Nat) (adrs : Types.Adrs) (val : Nat) (pos : Nat) :
    chainHash seed adrs val pos 0 = val := by
  rfl

/-- Chain hash composition: doing m steps then n steps equals doing m+n steps -/
theorem chainHash_compose (seed : Nat) (adrs : Types.Adrs) (val : Nat)
    (pos m n : Nat) :
    chainHash seed adrs (chainHash seed adrs val pos m) (pos + m) n =
    chainHash seed adrs val pos (m + n) := by
  induction m generalizing val pos with
  | zero => simp
  | succ m ih =>
    simp [chainHash]
    have : pos + 1 + m = pos + (m + 1) := by omega
    rw [this] at ih
    exact ih (th seed (withChainPos adrs pos) val) (pos + 1)

end WotsOts.Hash
