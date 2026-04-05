/-
  SphincsC6.Hash — Abstract hash primitives with cryptographic axioms.
  Models keccak256 tweakable hashing for SPHINCS+ C6 (n=128).
-/
import SphincsC6.Types

namespace SphincsC6

opaque th (seed : Hash128) (adrs : Adrs) (input : Hash128) : Hash128
opaque thPair (seed : Hash128) (adrs : Adrs) (left right : Hash128) : Hash128
opaque thMulti (seed : Hash128) (adrs : Adrs) (inputs : List Hash128) : Hash128
opaque hMsg (seed root R message : Hash128) : UInt256
opaque wotsDigest (seed : Hash128) (adrs : Adrs) (msgHash : Hash128) (count : Nat) : UInt256

axiom th_collision_resistant :
  ∀ (seed : Hash128) (adrs : Adrs) (x y : Hash128),
    th seed adrs x = th seed adrs y → x = y

axiom th_domain_separated :
  ∀ (seed : Hash128) (adrs1 adrs2 : Adrs) (x : Hash128),
    adrs1 ≠ adrs2 → th seed adrs1 x ≠ th seed adrs2 x

axiom thPair_collision_resistant :
  ∀ (seed : Hash128) (adrs : Adrs) (l1 r1 l2 r2 : Hash128),
    thPair seed adrs l1 r1 = thPair seed adrs l2 r2 → l1 = l2 ∧ r1 = r2

def chainHash (seed : Hash128) (adrs : Adrs) (val : Hash128) (startPos steps : Nat) : Hash128 :=
  match steps with
  | 0 => val
  | n + 1 =>
    let adrs' := adrs.withChainPos startPos
    let nextVal := th seed adrs' val
    chainHash seed adrs nextVal (startPos + 1) n

theorem chainHash_zero (seed : Hash128) (adrs : Adrs) (val : Hash128) (pos : Nat) :
    chainHash seed adrs val pos 0 = val := by simp [chainHash]

theorem chainHash_compose (seed : Hash128) (adrs : Adrs) (val : Hash128)
    (pos m n : Nat) :
    chainHash seed adrs (chainHash seed adrs val pos m) (pos + m) n =
    chainHash seed adrs val pos (m + n) := by
  induction m generalizing val pos with
  | zero => simp [chainHash]
  | succ k ih => simp [chainHash]; rw [Nat.add_assoc, ← ih]; ring_nf

end SphincsC6
