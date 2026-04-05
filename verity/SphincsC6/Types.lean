/-
  SphincsC6.Types — Core type definitions for C6: W+C_F+C
  h=24, d=2, a=16, k=8, w=16, l=32, subtree_h=12
-/

namespace SphincsC6

abbrev UInt256 := Nat
abbrev Hash128 := Nat

def N : Nat := 16
def H : Nat := 24
def D : Nat := 2
def SUBTREE_H : Nat := 12
def A : Nat := 16
def K : Nat := 8
def W : Nat := 16
def LOG_W : Nat := 4
def L : Nat := 32
def LEN1 : Nat := 32
def TARGET_SUM : Nat := 240
def Z : Nat := 0
def SIG_SIZE : Nat := 3352

-- ADRS types
inductive AdrsType where
  | wots | wotsPk | tree | forsTree | forsRoots | pors
  deriving BEq, Repr

structure Adrs where
  layer    : Nat := 0
  treeAddr : Nat := 0
  adrsType : AdrsType
  keyPair  : Nat := 0
  chainIdx : Nat := 0
  chainPos : Nat := 0
  hashAddr : Nat := 0
  deriving BEq, Repr

def Adrs.withChainPos (a : Adrs) (pos : Nat) : Adrs := { a with chainPos := pos }
def Adrs.withHeight (a : Adrs) (h : Nat) : Adrs := { a with chainPos := h }
def Adrs.withIndex (a : Adrs) (idx : Nat) : Adrs := { a with hashAddr := idx }

-- Signature components
structure WotsLayerSig where
  sigma    : Fin L → Hash128
  count    : Nat
  authPath : Fin SUBTREE_H → Hash128

structure ForsCSig where
  secrets  : Fin K → Hash128           -- k secrets (k-1 leaf secrets + 1 root)
  authPaths: Fin (K - 1) → Fin A → Hash128  -- k-1 auth paths of depth A

structure SphincsC6Sig where
  R        : Hash128
  fors     : ForsCSig
  htLayers : Fin D → WotsLayerSig

structure ContractState where
  pkSeed : Hash128
  pkRoot : Hash128

end SphincsC6
