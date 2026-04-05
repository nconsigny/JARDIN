/-
  SphincsC6.Contract — Full C6 SPHINCS+ verifier contract model (Verity EDSL).
-/
import SphincsC6.Types
import SphincsC6.Hash
import SphincsC6.WotsC
import SphincsC6.ForsC
import SphincsC6.Hypertree

namespace SphincsC6

def extractHtIdx (digest : UInt256) : Nat :=
  (digest / 2^(K * A)) % 2^H

def verify (state : ContractState) (message : Hash128) (sig : SphincsC6Sig) : Bool :=
  let seed := state.pkSeed
  let root := state.pkRoot
  let digest := hMsg seed root sig.R message
  let htIdx := extractHtIdx digest
  let forsPk := forsVerify seed digest sig.fors
  let computedRoot := do
    let pk ← forsPk
    hypertreeVerify seed htIdx pk sig.htLayers
  match computedRoot with
  | some r => r == root
  | none => false

-- EVM storage model
structure EvmState where
  storage : Nat → UInt256

def contractVerify (s : EvmState) (message : Hash128) (sig : SphincsC6Sig) : Bool :=
  verify { pkSeed := s.storage 0, pkRoot := s.storage 1 } message sig

opaque asmVerify (s : EvmState) (message : Hash128) (sigBytes : List UInt256) : Bool
opaque decodeSig (sigBytes : List UInt256) : Option SphincsC6Sig

axiom asm_model_equiv :
  ∀ (s : EvmState) (message : Hash128) (sig : SphincsC6Sig) (sigBytes : List UInt256),
    decodeSig sigBytes = some sig → asmVerify s message sigBytes = contractVerify s message sig

end SphincsC6
