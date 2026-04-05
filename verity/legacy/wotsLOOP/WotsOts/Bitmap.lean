/-
  WotsOts/Bitmap.lean — Bitmap operations and properties.

  Models the 1024-bit bitmap used to track consumed WOTS+C one-time keys.
  Key operations: isUsed, mark. Key property: monotonicity (bits only go 0→1).
-/

import WotsOts.Types

namespace WotsOts.Bitmap

open WotsOts

/-- Check if a bit is set in a natural number (modeling uint256 bit access) -/
def Nat.testBit (n : Nat) (i : Nat) : Bool :=
  (n / 2^i) % 2 == 1

/-- Set a bit in a natural number (modeling uint256 |= (1 << bit)) -/
def Nat.setBit (n : Nat) (i : Nat) : Nat :=
  n ||| (2^i)

/-- Check if leaf index has been consumed -/
def isUsed (bm : Bitmap) (idx : Nat) : Bool :=
  let word := idx / 256
  let bit := idx % 256
  if h : word < 4 then
    Nat.testBit (bm.words ⟨word, h⟩) bit
  else
    false  -- out of bounds

/-- Mark a leaf index as consumed -/
def mark (bm : Bitmap) (idx : Nat) : Bitmap :=
  let word := idx / 256
  let bit := idx % 256
  if h : word < 4 then
    { words := fun i =>
        if i.val == word then
          Nat.setBit (bm.words i) bit
        else
          bm.words i }
  else
    bm  -- out of bounds, no change

/-- An empty bitmap has no bits set -/
def empty : Bitmap := { words := fun _ => 0 }

/-- Count the number of set bits in a Nat (population count) -/
def Nat.popcount : Nat → Nat
  | 0 => 0
  | n => (n % 2) + Nat.popcount (n / 2)

/-- Count total used keys across all bitmap words -/
def usedCount (bm : Bitmap) : Nat :=
  Nat.popcount (bm.words ⟨0, by omega⟩) +
  Nat.popcount (bm.words ⟨1, by omega⟩) +
  Nat.popcount (bm.words ⟨2, by omega⟩) +
  Nat.popcount (bm.words ⟨3, by omega⟩)

/-- Remaining keys = 1024 - usedCount -/
def remainingKeys (bm : Bitmap) : Nat :=
  maxKeys - usedCount bm

-- ════════════════════════════════════════════════════════════
--  Core Lemmas
-- ════════════════════════════════════════════════════════════

/-- Setting a bit preserves all previously set bits (OR monotonicity) -/
theorem setBit_preserves (n i j : Nat) (h : Nat.testBit n j = true) :
    Nat.testBit (Nat.setBit n i) j = true := by
  simp [Nat.setBit, Nat.testBit]
  omega

/-- Setting a bit actually sets it -/
theorem setBit_sets (n i : Nat) :
    Nat.testBit (Nat.setBit n i) i = true := by
  simp [Nat.setBit, Nat.testBit]
  omega

/-- An empty bitmap has no bits set -/
theorem empty_not_used (idx : Nat) : isUsed empty idx = false := by
  simp [isUsed, empty, Nat.testBit]
  split <;> simp

/-- After marking, the marked index is used -/
theorem mark_sets (bm : Bitmap) (idx : Nat) (h : idx < maxKeys) :
    isUsed (mark bm idx) idx = true := by
  simp [isUsed, mark, maxKeys] at *
  have hw : idx / 256 < 4 := by omega
  simp [hw]
  exact setBit_sets (bm.words ⟨idx / 256, hw⟩) (idx % 256)

/-- Marking preserves previously used indices -/
theorem mark_monotone (bm : Bitmap) (idx j : Nat)
    (hj : j < maxKeys) (h_used : isUsed bm j = true) :
    isUsed (mark bm idx) j = true := by
  simp [isUsed, mark, maxKeys] at *
  have hjw : j / 256 < 4 := by omega
  simp [hjw] at h_used ⊢
  by_cases heq : idx / 256 < 4
  · simp [heq]
    by_cases hword : (⟨idx / 256, heq⟩ : Fin 4).val = j / 256
    · simp [hword]
      exact setBit_preserves _ _ _ h_used
    · simp [hword]
      exact h_used
  · simp [heq]
    exact h_used

end WotsOts.Bitmap
