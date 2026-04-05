/-
  SphincsC6.WotsC — WOTS+C verification for w=16, l=32 chains.
-/
import SphincsC6.Types
import SphincsC6.Hash

namespace SphincsC6

def extractDigit (val : UInt256) (i : Nat) : Nat :=
  (val / 2^(i * LOG_W)) % W

def extractDigits (val : UInt256) : Fin L → Nat :=
  fun i => extractDigit val i.val

def digitSum (val : UInt256) : Nat :=
  (List.range L).foldl (fun acc i => acc + extractDigit val i) 0

def verifyChain (seed : Hash128) (leafIdx chainIdx layer treeAddr : Nat)
    (sigma_i : Hash128) (digit_i : Nat) : Hash128 :=
  let steps := W - 1 - digit_i
  let adrs : Adrs := {
    layer := layer, treeAddr := treeAddr, adrsType := .wots,
    keyPair := leafIdx, chainIdx := chainIdx
  }
  chainHash seed adrs sigma_i digit_i steps

def compressPk (seed : Hash128) (layer treeAddr leafIdx : Nat)
    (endpoints : Fin L → Hash128) : Hash128 :=
  let adrs : Adrs := {
    layer := layer, treeAddr := treeAddr, adrsType := .wotsPk, keyPair := leafIdx
  }
  thMulti seed adrs (List.ofFn endpoints)

def wotsVerify (seed : Hash128) (layer treeAddr leafIdx : Nat)
    (msgHash : Hash128) (sigma : Fin L → Hash128) (count : Nat)
    : Option Hash128 := do
  let adrs : Adrs := {
    layer := layer, treeAddr := treeAddr, adrsType := .wots, keyPair := leafIdx
  }
  let d := wotsDigest seed adrs msgHash count
  guard (digitSum d = TARGET_SUM)
  let endpoints : Fin L → Hash128 := fun i =>
    verifyChain seed leafIdx i.val layer treeAddr (sigma i) (extractDigit d i.val)
  return compressPk seed layer treeAddr leafIdx endpoints

theorem extractDigit_bound (val : UInt256) (i : Nat) : extractDigit val i < W := by
  simp [extractDigit, W]; exact Nat.mod_lt _ (by omega)

end SphincsC6
