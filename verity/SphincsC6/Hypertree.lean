/-
  SphincsC6.Hypertree — Hypertree verification (D=2 layers, subtree_h=12).
-/
import SphincsC6.Types
import SphincsC6.Hash
import SphincsC6.WotsC

namespace SphincsC6

def merkleAuthPath (seed : Hash128) (layer treeAddr : Nat)
    (leaf : Hash128) (authPath : Fin SUBTREE_H → Hash128) (leafIdx : Nat)
    : Hash128 :=
  let rec loop (h : Nat) (node : Hash128) (idx : Nat) : Hash128 :=
    if h_lt : h < SUBTREE_H then
      let sibling := authPath ⟨h, h_lt⟩
      let parent := idx / 2
      let adrs : Adrs := {
        layer := layer, treeAddr := treeAddr, adrsType := .tree,
        chainPos := h + 1, hashAddr := parent
      }
      let (left, right) := if idx % 2 == 0 then (node, sibling) else (sibling, node)
      let parentHash := thPair seed adrs left right
      loop (h + 1) parentHash parent
    else node
  loop 0 leaf leafIdx

def verifyHtLayer (seed : Hash128) (layer treeAddr leafIdx : Nat)
    (currentNode : Hash128) (layerSig : WotsLayerSig) : Option Hash128 := do
  let wotsPk ← wotsVerify seed layer treeAddr leafIdx
                  currentNode layerSig.sigma layerSig.count
  return merkleAuthPath seed layer treeAddr wotsPk layerSig.authPath leafIdx

def hypertreeVerify (seed : Hash128) (htIdx : Nat) (bottomPk : Hash128)
    (htLayers : Fin D → WotsLayerSig) : Option Hash128 := do
  let mut currentNode := bottomPk
  let mut idxTree := htIdx
  for h_layer : layer in List.range D do
    let idxLeaf := idxTree % 2^SUBTREE_H
    idxTree := idxTree / 2^SUBTREE_H
    currentNode ← verifyHtLayer seed layer idxTree idxLeaf currentNode
                     (htLayers ⟨layer, by omega⟩)
  return currentNode

end SphincsC6
