"""
JARDÍN shared primitives — keccak256, 32-byte ADRS, tweakable hash.

Used by every current signer:
    jardin_spx_signer.py         (SPX / plain-SPHINCS+ registration path)
    jardin_fors_plain_signer.py  (plain-FORS / compact path)

ADRS layout (32 bytes, four uint32 words + a uint64 tree word):
    bytes  0..3   layer        uint32
    bytes  4..11  tree         uint64
    bytes 12..15  type         uint32
    bytes 16..19  kp           uint32   (keyPair)
    bytes 20..23  ci           uint32   (chain index / 0 for FORS trees)
    bytes 24..27  cp           uint32   (chain position / tree height)
    bytes 28..31  ha           uint32   (hash address / tree index)

Tweakable hash primitives (keccak256 truncated to 16B):
    th(seed32, adrs32, in16)                     — 64 B input  (seed‖adrs‖in32)
    th_pair(seed32, adrs32, L16, R16)            — 128 B input (seed‖adrs‖L32‖R32)
    th_multi(seed32, adrs32, [v_i 16B each])     — (seed‖adrs‖v0..vN) variable

All 16-byte values live in the high 16 bytes of a 256-bit word with the low
16 bytes zeroed — matching the on-chain convention (`pkSeed` bytes32 with
value in high bytes, low 16 bytes zero).
"""

import hmac, hashlib, struct
from Crypto.Hash import keccak as _keccak_mod

# ============================================================
#  Sizing + masks
# ============================================================

N      = 16
N_MASK = (1 << 256) - (1 << 128)   # clears the low 128 bits
FULL   = (1 << 256) - 1

# ADRS types (JARDÍN family)
ADRS_WOTS_HASH     = 0
ADRS_WOTS_PK       = 1
ADRS_XMSS_TREE     = 2
ADRS_FORS_TREE     = 3
ADRS_FORS_ROOTS    = 4
ADRS_JARDIN_MERKLE = 16

# ============================================================
#  keccak256
# ============================================================

def keccak256(data: bytes) -> int:
    h = _keccak_mod.new(digest_bits=256)
    h.update(data)
    return int.from_bytes(h.digest(), "big")

def keccak256_bytes(data: bytes) -> bytes:
    h = _keccak_mod.new(digest_bits=256)
    h.update(data)
    return h.digest()

def to_b32(val: int) -> bytes:
    return (val & FULL).to_bytes(32, "big")

def to_b4(val: int) -> bytes:
    return struct.pack(">I", val & 0xFFFFFFFF)

# ============================================================
#  Zero-copy 3-/4-value keccak helpers (hot path for FORS/XMSS)
# ============================================================

_BUF96  = bytearray(96)
_BUF128 = bytearray(128)

def _keccak_3x32(a, b, c):
    _BUF96[ 0:32] = a.to_bytes(32, "big")
    _BUF96[32:64] = b.to_bytes(32, "big")
    _BUF96[64:96] = c.to_bytes(32, "big")
    h = _keccak_mod.new(digest_bits=256)
    h.update(_BUF96)
    return int.from_bytes(h.digest(), "big")

def _keccak_4x32(a, b, c, d):
    _BUF128[  0:32 ] = a.to_bytes(32, "big")
    _BUF128[ 32:64 ] = b.to_bytes(32, "big")
    _BUF128[ 64:96 ] = c.to_bytes(32, "big")
    _BUF128[ 96:128] = d.to_bytes(32, "big")
    h = _keccak_mod.new(digest_bits=256)
    h.update(_BUF128)
    return int.from_bytes(h.digest(), "big")

# ============================================================
#  ADRS packer + tweakable hash
# ============================================================

def make_adrs(layer, tree, atype, kp, ci, cp, ha):
    return ((layer & 0xFFFFFFFF)         << 224 |
            (tree  & 0xFFFFFFFFFFFFFFFF) << 160 |
            (atype & 0xFFFFFFFF)         << 128 |
            (kp    & 0xFFFFFFFF)         <<  96 |
            (ci    & 0xFFFFFFFF)         <<  64 |
            (cp    & 0xFFFFFFFF)         <<  32 |
            (ha    & 0xFFFFFFFF))

def th(seed, adrs, inp):
    """keccak(seed32 || adrs32 || inp32)[0..15]."""
    return _keccak_3x32(seed, adrs, inp) & N_MASK

def th_pair(seed, adrs, left, right):
    """keccak(seed32 || adrs32 || left32 || right32)[0..15]."""
    return _keccak_4x32(seed, adrs, left, right) & N_MASK

def th_multi(seed, adrs, vals):
    """keccak(seed32 || adrs32 || v0_32 || v1_32 || ...)[0..15]."""
    data = to_b32(seed) + to_b32(adrs)
    for v in vals:
        data += to_b32(v)
    return keccak256(data) & N_MASK

# ============================================================
#  BIP-39-ish key derivation helpers (used by signers' CLI modes)
# ============================================================

def hmac512(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha512).digest()
