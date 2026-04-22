#!/usr/bin/env python3
"""
JARDÍN plain-FORS compact-path signer (variable h).

Parameters:
    n = 16 bytes (128-bit keccak truncation)
    k = 32      FORS trees revealed per signature
    a = 4       FORS tree height → 16 leaves/tree
    R = 32 B    per-signature randomness
    h ∈ [2, 8]  outer balanced Merkle tree height (Q_MAX = 2^h)

Replaces FORS+C as Type 2. No counter grinding, no forced-zero last tree:
every one of the k=32 FORS trees reveals one leaf secret + full auth path.
Security at r=1 is k·a = 128 bits (one-time).

Signature layout (2593 + 16·h bytes):
    R(32) | K=32 × (sk 16B + auth 4×16B) = 2560 | q(1) | merkleAuth(h × 16)

ADRS and tweakable hash identical to the existing JardinForsCVerifier
convention (layer‖tree‖type‖kp‖ci=q‖cp=height‖ha=y, 32-byte packed). This
file reuses jardin_signer.make_adrs / th / th_pair / th_multi / keccak256 /
to_b32 / to_b4 helpers.

H_msg (160 B, no counter field):
    keccak256(seed ‖ root ‖ R ‖ msg ‖ 0xFF..FD)
Domain 0xFF..FD is distinct from C11 (FF..FF), T0 (FF..FE) and the 192-B
FORS+C H_msg (which carries a counter).

Usage:
    python3 script/jardin_fors_plain_signer.py <message_hex> [q] [h]

Output: ABI-encoded (bytes32 seed, bytes32 root, bytes sig) hex on stdout.
"""

import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from jardin_signer import (
    keccak256, to_b32, to_b4,
    make_adrs, th, th_pair, th_multi,
    ADRS_FORS_TREE, ADRS_FORS_ROOTS, ADRS_JARDIN_MERKLE,
    N, N_MASK, FULL,
    jardin_derive_keys,
)

# ============================================================
#  Parameters
# ============================================================

K = 32
A = 4
A_MASK = (1 << A) - 1   # 0xF

MIN_H = 2
MAX_H = 8

FORS_BODY_LEN = K * (N + A * N)          # 32 × 80 = 2560
R_LEN         = 32
Q_LEN         = 1
BASE_LEN      = R_LEN + FORS_BODY_LEN + Q_LEN   # 2593

def fors_sig_len(h):
    return BASE_LEN + h * N

# Domain separator for Hmsg (distinct from C11/T0/FORS+C)
HMSG_DOMAIN_PLAIN = FULL - 2  # 0xFF..FD

# ============================================================
#  Secret derivation (reuses jardin_derive_keys for sub-key material)
# ============================================================

def plain_fors_secret(sk_seed, q, tree_idx, leaf_idx):
    """Per-leaf FORS secret — same tag scheme as existing JARDIN compact."""
    data = to_b32(sk_seed) + b"jardin_fors_plain" + to_b4(q) + to_b4(tree_idx) + to_b4(leaf_idx)
    return keccak256(data) & N_MASK

# ============================================================
#  Tweakable hash primitives already imported from jardin_signer
# ============================================================

def h_msg(seed, root, R, message):
    data = (to_b32(seed) + to_b32(root) + to_b32(R) +
            to_b32(message) + to_b32(HMSG_DOMAIN_PLAIN))
    return keccak256(data)

# ============================================================
#  Plain-FORS tree (ADRS matches FORS+C: kp=0, ci=q, x=height, y=global)
# ============================================================

def build_plain_fors_tree(seed, sk_seed, q, tree_idx):
    """Returns (levels, root) where levels[0] = leaves, levels[A] = [root]."""
    n_leaves = 1 << A
    leaves = []
    for j in range(n_leaves):
        secret = plain_fors_secret(sk_seed, q, tree_idx, j)
        global_y = (tree_idx << A) | j
        leaf_adrs = make_adrs(0, 0, ADRS_FORS_TREE, 0, q, 0, global_y)
        leaves.append(th(seed, leaf_adrs, secret))
    nodes = [leaves]
    for h in range(A):
        prev = nodes[h]
        level = []
        for idx in range(0, len(prev), 2):
            parent_idx = idx // 2
            global_y = (tree_idx << (A - h - 1)) | parent_idx
            adrs = make_adrs(0, 0, ADRS_FORS_TREE, 0, q, h + 1, global_y)
            level.append(th_pair(seed, adrs, prev[idx], prev[idx + 1]))
        nodes.append(level)
    return nodes, nodes[A][0]

def get_auth_path(tree_nodes, leaf_idx, height):
    path = []
    idx = leaf_idx
    for h in range(height):
        path.append(tree_nodes[h][idx ^ 1])
        idx >>= 1
    return path

def compute_fors_plain_pk(seed, sk_seed, q):
    roots = []
    for t in range(K):
        _, root = build_plain_fors_tree(seed, sk_seed, q, t)
        roots.append(root)
    roots_adrs = make_adrs(0, 0, ADRS_FORS_ROOTS, 0, q, 0, 0)
    return th_multi(seed, roots_adrs, roots)

# ============================================================
#  Outer balanced Merkle tree over Q_MAX = 2^h FORS public keys
# ============================================================

def build_balanced_tree(seed, sk_seed, h):
    if not (MIN_H <= h <= MAX_H):
        raise ValueError(f"h={h} outside [{MIN_H}, {MAX_H}]")
    q_max = 1 << h
    fors_pks = []
    for q in range(1, q_max + 1):
        eprint(f"  FORS-plain PK q={q}/{q_max}...")
        fors_pks.append(compute_fors_plain_pk(seed, sk_seed, q))

    levels = [None] * (h + 1)
    levels[h] = fors_pks
    for level in range(h - 1, -1, -1):
        layer = []
        child_layer = levels[level + 1]
        for i in range(1 << level):
            adrs = make_adrs(0, 0, ADRS_JARDIN_MERKLE, 0, 0, level, i)
            left = child_layer[2 * i]
            right = child_layer[2 * i + 1]
            layer.append(th_pair(seed, adrs, left, right))
        levels[level] = layer
    return levels, levels[0][0]

def get_balanced_auth_path(levels, q, h):
    leaf_idx = q - 1
    auth = []
    idx = leaf_idx
    for j in range(h):
        child_level = h - j
        auth.append(levels[child_level][idx ^ 1])
        idx >>= 1
    return auth

# ============================================================
#  Signing
# ============================================================

def derive_R(sk_seed, message, q):
    return keccak256(to_b32(sk_seed) + b"jardin_fors_plain_R" + to_b32(message) + to_b4(q))

def fors_plain_sign(seed, sk_seed, pk_root, levels, message, q, h):
    R = derive_R(sk_seed, message, q)
    digest = h_msg(seed, pk_root, R, message)
    # LSB-first parsing of k indices (same convention as FORS+C)
    indices = [(digest >> (t * A)) & A_MASK for t in range(K)]

    secrets = []
    auth_paths = []
    for t in range(K):
        tree_nodes, _ = build_plain_fors_tree(seed, sk_seed, q, t)
        secrets.append(plain_fors_secret(sk_seed, q, t, indices[t]))
        auth_paths.append(get_auth_path(tree_nodes, indices[t], A))

    outer_auth = get_balanced_auth_path(levels, q, h)

    sig = to_b32(R)
    for t in range(K):
        sig += to_b32(secrets[t])[:N]
        for node in auth_paths[t]:
            sig += to_b32(node)[:N]
    sig += bytes([q & 0xFF])
    for node in outer_auth:
        sig += to_b32(node)[:N]

    expected = fors_sig_len(h)
    assert len(sig) == expected, f"sig len {len(sig)} != {expected}"
    return sig, R, digest

# ============================================================
#  Local verifier (mirror of on-chain Yul, byte-for-byte)
# ============================================================

def fors_plain_verify(seed, pk_root, message, sig):
    total = len(sig)
    merkle_bytes = total - BASE_LEN
    assert merkle_bytes >= 0 and merkle_bytes % N == 0, f"bad sig length {total}"
    h = merkle_bytes // N
    assert MIN_H <= h <= MAX_H, f"h={h} outside [{MIN_H}, {MAX_H}]"

    R = int.from_bytes(sig[:32], "big")
    q = sig[R_LEN + FORS_BODY_LEN]
    assert 1 <= q <= (1 << h), f"bad q={q}"
    leaf_idx = q - 1

    digest = h_msg(seed, pk_root, R, message)
    indices = [(digest >> (t * A)) & A_MASK for t in range(K)]

    # FORS tree verification
    roots = []
    off = R_LEN
    for t in range(K):
        secret = int.from_bytes(sig[off:off + N], "big") << 128
        leaf_adrs = make_adrs(0, 0, ADRS_FORS_TREE, 0, q, 0, (t << A) | indices[t])
        node = th(seed, leaf_adrs, secret)
        path_idx = indices[t]
        for hh in range(A):
            sib_off = off + N + hh * N
            sib = int.from_bytes(sig[sib_off:sib_off + N], "big") << 128
            parent_idx = path_idx >> 1
            global_y = (t << (A - hh - 1)) | parent_idx
            adrs = make_adrs(0, 0, ADRS_FORS_TREE, 0, q, hh + 1, global_y)
            if path_idx & 1 == 0:
                node = th_pair(seed, adrs, node, sib)
            else:
                node = th_pair(seed, adrs, sib, node)
            path_idx = parent_idx
        roots.append(node)
        off += N + A * N

    roots_adrs = make_adrs(0, 0, ADRS_FORS_ROOTS, 0, q, 0, 0)
    fors_pk = th_multi(seed, roots_adrs, roots)

    # Outer Merkle walk
    auth_off = R_LEN + FORS_BODY_LEN + 1
    node = fors_pk
    for j in range(h):
        sib_bytes = sig[auth_off + j * N : auth_off + (j + 1) * N]
        sib = int.from_bytes(sib_bytes, "big") << 128
        level = h - 1 - j
        parent_idx = leaf_idx >> (j + 1)
        adrs = make_adrs(0, 0, ADRS_JARDIN_MERKLE, 0, 0, level, parent_idx)
        bit = (leaf_idx >> j) & 1
        if bit == 0:
            node = th_pair(seed, adrs, node, sib)
        else:
            node = th_pair(seed, adrs, sib, node)
    return node == pk_root

# ============================================================
#  CLI
# ============================================================

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def abi_encode(seed, root, sig):
    enc = to_b32(seed) + to_b32(root) + to_b32(0x60) + to_b32(len(sig))
    enc += sig + b"\x00" * ((32 - len(sig) % 32) % 32)
    return enc

def main():
    if len(sys.argv) < 2:
        eprint("Usage: jardin_fors_plain_signer.py <message_hex> [q=1] [h=7]")
        sys.exit(1)
    msg_hex = sys.argv[1].replace("0x", "")
    if len(msg_hex) % 2:
        msg_hex = "0" + msg_hex
    message = int(msg_hex, 16) if msg_hex else 0
    q  = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    h  = int(sys.argv[3]) if len(sys.argv) > 3 else 7

    t0 = time.time()
    # Use a fixed test entropy (matches the existing jardin_signer CLI style)
    seed, sk_seed = jardin_derive_keys(0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef)
    eprint(f"  pkSeed={hex(seed)[:18]}...")
    eprint(f"  Building outer Merkle tree (h={h}, Q_MAX={1 << h})...")
    levels, pk_root = build_balanced_tree(seed, sk_seed, h)
    eprint(f"  pkRoot={hex(pk_root)[:18]}...")

    eprint(f"  Signing q={q}...")
    sig, R, digest = fors_plain_sign(seed, sk_seed, pk_root, levels, message, q, h)
    assert fors_plain_verify(seed, pk_root, message, sig), "local verify failed"
    eprint(f"  OK. sig={len(sig)}B, total={time.time()-t0:.1f}s")

    print("0x" + abi_encode(seed, pk_root, sig).hex())

if __name__ == "__main__":
    main()
