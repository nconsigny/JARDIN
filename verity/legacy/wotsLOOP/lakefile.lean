import Lake
open Lake DSL

package WotsOtsVerity where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib WotsOts where
  srcDir := "WotsOts"
  roots := #[`Types, `Bitmap, `Hash, `WotsC, `MerkleTree, `Contract, `Spec]

lean_lib Proofs where
  srcDir := "WotsOts/Proofs"
  roots := #[`BitmapMonotonicity, `OneTimeUse, `KeyExhaustion, `SolidityBridge]
