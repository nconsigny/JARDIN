/-
  WotsOts/MerkleTree.lean — Merkle tree model for key management.

  Models the H=10 Merkle tree of WOTS+C public keys used in WotsOts.sol.
  The root commits to all 1024 one-time keys; auth paths prove leaf membership.
-/

import WotsOts.Types
import WotsOts.Hash

namespace WotsOts.MerkleTree

open WotsOts WotsOts.Hash

/-- A Merkle tree is defined by its leaves and the hash function used -/
structure MerkleTree where
  height : Nat
  leaves : Fin (2^height) → Nat
  seed   : Nat

/-- Compute a Merkle tree node at a given level and index.
    Level 0 = leaves, level h = root. -/
def computeNode (t : MerkleTree) : (level : Nat) → (idx : Nat) → Nat
  | 0, idx => if h : idx < 2^t.height then t.leaves ⟨idx, h⟩ else 0
  | level + 1, idx =>
    let left := computeNode t level (2 * idx)
    let right := computeNode t level (2 * idx + 1)
    let adrs : Types.Adrs := {
      adrsType := .tree
      chainPos := level + 1  -- height field in ADRS
      hashAddr := idx         -- node index in ADRS
    }
    thPair t.seed adrs left right

/-- The root of a Merkle tree -/
def root (t : MerkleTree) : Nat :=
  computeNode t t.height 0

/-- An authentication path: H sibling hashes -/
def AuthPath (h : Nat) := Fin h → Nat

/-- Verify a Merkle authentication path.
    Given a leaf value and its index, walk the path to reconstruct the root. -/
def verifyPath (seed : Nat) (leaf : Nat) (leafIdx : Nat) (path : AuthPath 10) : Nat :=
  let rec go (node : Nat) (idx : Nat) : (level : Nat) → Nat
    | 0 => node
    | level + 1 =>
      let h := 10 - level - 1  -- current height (0-indexed from bottom)
      let sibling := path ⟨h, by omega⟩
      let parentIdx := idx / 2
      let adrs : Types.Adrs := {
        adrsType := .tree
        chainPos := h + 1
        hashAddr := parentIdx
      }
      let (left, right) := if idx % 2 == 0 then (node, sibling) else (sibling, node)
      let parent := thPair seed adrs left right
      go parent parentIdx level
  go leaf leafIdx 10

/-- A valid auth path reconstructs the correct root -/
def validPath (seed : Nat) (root : Nat) (leaf : Nat) (leafIdx : Nat) (path : AuthPath 10) : Prop :=
  verifyPath seed leaf leafIdx path = root

-- ════════════════════════════════════════════════════════════
--  Properties
-- ════════════════════════════════════════════════════════════

/-- Auth path verification is deterministic: same inputs always produce the same result -/
theorem verifyPath_deterministic (seed leaf leafIdx : Nat) (path : AuthPath 10) :
    verifyPath seed leaf leafIdx path = verifyPath seed leaf leafIdx path := by
  rfl

/-- Different leaves (with collision-resistant hash) produce different roots
    when using the same auth path. This is the binding property of Merkle trees. -/
theorem merkle_binding (seed : Nat) (leaf1 leaf2 : Nat) (leafIdx : Nat)
    (path : AuthPath 10) (h : leaf1 ≠ leaf2) :
    verifyPath seed leaf1 leafIdx path ≠ verifyPath seed leaf2 leafIdx path := by
  -- Follows from collision resistance of thPair, propagating through each level.
  -- Formal proof requires induction on the path + collision resistance axiom.
  sorry -- Requires th_collision_resistant applied at each Merkle level

end WotsOts.MerkleTree
