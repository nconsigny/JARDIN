/-
  SphincsC6.ForsC — FORS+C verification with forced-zero last tree.
  K=8 trees of height A=16, last tree forced to index 0 via R-grinding.
-/
import SphincsC6.Types
import SphincsC6.Hash

namespace SphincsC6

-- ============================================================
-- Index Extraction
-- ============================================================

/-- Extract K FORS indices from digest, each A bits wide. -/
def extractForsIndices (digest : UInt256) : Fin K → Nat :=
  fun i => (digest / 2^(i.val * A)) % 2^A

/-- The last index (k-1) must be zero (forced by R-grinding). -/
def forcedZeroValid (digest : UInt256) : Bool :=
  extractForsIndices digest ⟨K - 1, by omega⟩ == 0

-- ============================================================
-- Single Tree Verification
-- ============================================================

/-- Verify one FORS tree: hash secret to leaf, walk auth path to root. -/
def verifyForsTree (seed : Hash128) (treeIdx : Nat) (leafIdx : Nat)
    (secret : Hash128) (authPath : Fin A → Hash128) : Hash128 :=
  -- Leaf hash
  let leafAdrs : Adrs := {
    adrsType := .forsTree, keyPair := treeIdx, hashAddr := leafIdx
  }
  let leaf := th seed leafAdrs secret

  -- Walk auth path
  let rec walkAuth (h : Nat) (node : Hash128) (idx : Nat) : Hash128 :=
    if h_lt : h < A then
      let sibling := authPath ⟨h, h_lt⟩
      let parent := idx / 2
      let adrs : Adrs := {
        adrsType := .forsTree, keyPair := treeIdx,
        chainPos := h + 1, hashAddr := parent
      }
      let (left, right) := if idx % 2 == 0 then (node, sibling) else (sibling, node)
      let parentHash := thPair seed adrs left right
      walkAuth (h + 1) parentHash parent
    else
      node
  walkAuth 0 leaf leafIdx

/-- Hash the forced-zero tree's root: th(seed, adrs, secret). -/
def hashForcedZeroRoot (seed : Hash128) (treeIdx : Nat) (secret : Hash128) : Hash128 :=
  let adrs : Adrs := { adrsType := .forsTree, keyPair := treeIdx }
  th seed adrs secret

-- ============================================================
-- Full FORS+C Verification
-- ============================================================

/-- Verify FORS+C: k-1 trees with auth paths + 1 forced-zero tree.
    Returns the FORS public key (compressed roots). -/
def forsVerify (seed : Hash128) (digest : UInt256)
    (sig : ForsCSig) : Option Hash128 := do
  -- Check forced-zero constraint
  guard (forcedZeroValid digest)

  let indices := extractForsIndices digest

  -- Verify k-1 normal trees
  let mut roots : List Hash128 := []
  for h_i : i in List.range (K - 1) do
    let treeRoot := verifyForsTree seed i (indices ⟨i, by omega⟩)
                      (sig.secrets ⟨i, by omega⟩) (sig.authPaths ⟨i, by omega⟩)
    roots := roots ++ [treeRoot]

  -- Forced-zero tree: secret is the root itself
  let lastRoot := hashForcedZeroRoot seed (K - 1) (sig.secrets ⟨K - 1, by omega⟩)
  roots := roots ++ [lastRoot]

  -- Compress K roots into FORS PK
  let rootsAdrs : Adrs := { adrsType := .forsRoots }
  return thMulti seed rootsAdrs roots

-- ============================================================
-- Properties
-- ============================================================

/-- Each FORS index is bounded by 2^A. -/
theorem forsIndex_bound (digest : UInt256) (i : Fin K) :
    extractForsIndices digest i < 2^A := by
  simp [extractForsIndices]
  exact Nat.mod_lt _ (by positivity)

/-- K * A = 128: FORS indices consume exactly the lower 128 bits of digest. -/
theorem fors_bits_used : K * A = 128 := by simp [K, A]

end SphincsC6
