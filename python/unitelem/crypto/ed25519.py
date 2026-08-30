"""
Ed25519 asymmetric cryptography implementation (RFC 8032).

Provides high-speed zero-trust signing and verification.
If the C-based `cryptography` package is installed, it delegates to it for maximum performance.
Otherwise, it runs a self-contained pure-Python RFC 8032 Ed25519 implementation using standard library `hashlib` and `os`.
"""

import os
import hashlib
from typing import Tuple, Union

# Try importing the accelerated C library if available
_HAS_CRYPTOGRAPHY = False
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _c_ed25519
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    pass


# --------------------------------------------------------------------------
# Pure Python RFC 8032 Ed25519 Math
# --------------------------------------------------------------------------

_b = 256
_q = 2**255 - 19
_l = 2**252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, _q - 2, _q) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = 4 * _inv(5) % _q
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q, 1, (_Bx * _By) % _q)


def _edwards_add(P: Tuple[int, int, int, int], Q: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    # Extended coordinates addition
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    A = ((y1 - x1) * (y2 - x2)) % _q
    B = ((y1 + x1) * (y2 + x2)) % _q
    C = (t1 * 2 * _d * t2) % _q
    D = (z1 * 2 * z2) % _q
    E = (B - A) % _q
    F = (D - C) % _q
    G = (D + C) % _q
    H = (B + A) % _q
    return ((E * F) % _q, (G * H) % _q, (F * G) % _q, (E * H) % _q)


def _scalarmult(P: Tuple[int, int, int, int], e: int) -> Tuple[int, int, int, int]:
    if e == 0:
        return (0, 1, 1, 0)
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _encodepoint(P: Tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = P
    zi = _inv(z)
    x_val = (x * zi) % _q
    y_val = (y * zi) % _q
    bits = [(y_val >> i) & 1 for i in range(_b - 1)] + [x_val & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(_b // 8))


def _decodepoint(s: bytes) -> Tuple[int, int, int, int]:
    if len(s) != 32:
        raise ValueError("Invalid public key length")
    y = sum(2**i * ((s[i // 8] >> (i % 8)) & 1) for i in range(_b - 1))
    x = _xrecover(y)
    if bool(x & 1) != bool((s[_b // 8 - 1] >> 7) & 1):
        x = _q - x
    P = (x, y, 1, (x * y) % _q)
    return P


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="little")


def _pure_publickey(sk: bytes) -> bytes:
    h = _H(sk)
    a = 2**(_b - 2) + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, _b - 2))
    A = _scalarmult(_B, a)
    return _encodepoint(A)


def _pure_sign(sk: bytes, pk: bytes, m: bytes) -> bytes:
    h = _H(sk)
    a = 2**(_b - 2) + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, _b - 2))
    r = _int_from_bytes(_H(h[32:] + m)) % _l
    R = _scalarmult(_B, r)
    R_bytes = _encodepoint(R)
    k = _int_from_bytes(_H(R_bytes + pk + m)) % _l
    S = (r + k * a) % _l
    return R_bytes + S.to_bytes(32, byteorder="little")


def _pure_verify(pk: bytes, m: bytes, sig: bytes) -> bool:
    if len(sig) != 64 or len(pk) != 32:
        return False
    try:
        R_bytes = sig[:32]
        S_bytes = sig[32:]
        S = _int_from_bytes(S_bytes)
        if S >= _l:
            return False
        A = _decodepoint(pk)
        k = _int_from_bytes(_H(R_bytes + pk + m)) % _l
        SB = _scalarmult(_B, S)
        kA = _scalarmult(A, k)
        R = _decodepoint(R_bytes)
        R_plus_kA = _edwards_add(R, kA)
        return _encodepoint(SB) == _encodepoint(R_plus_kA)
    except Exception:
        return False


# --------------------------------------------------------------------------
# Public High-Level Object-Oriented API
# --------------------------------------------------------------------------

class Ed25519PublicKey:
    """Represents a 32-byte Ed25519 public key."""

    def __init__(self, raw_bytes: bytes):
        if len(raw_bytes) != 32:
            raise ValueError(f"Public key must be exactly 32 bytes, got {len(raw_bytes)}")
        self._raw_bytes = bytes(raw_bytes)
        self._c_key = None
        if _HAS_CRYPTOGRAPHY:
            try:
                self._c_key = _c_ed25519.Ed25519PublicKey.from_public_bytes(self._raw_bytes)
            except Exception:
                self._c_key = None

    def public_bytes(self) -> bytes:
        return self._raw_bytes

    def verify(self, signature: bytes, message: bytes) -> bool:
        """Verifies a 64-byte signature for the given message."""
        if len(signature) != 64:
            return False
        if self._c_key is not None:
            try:
                self._c_key.verify(signature, message)
                return True
            except Exception:
                return False
        return _pure_verify(self._raw_bytes, message, signature)

    def to_hex(self) -> str:
        return self._raw_bytes.hex()

    @classmethod
    def from_hex(cls, hex_str: str) -> "Ed25519PublicKey":
        return cls(bytes.fromhex(hex_str))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ed25519PublicKey):
            return False
        return self._raw_bytes == other._raw_bytes

    def __hash__(self) -> int:
        return hash(self._raw_bytes)

    def __repr__(self) -> str:
        return f"<Ed25519PublicKey {self._raw_bytes[:8].hex()}...>"


class Ed25519PrivateKey:
    """Represents a 32-byte Ed25519 seed/private key."""

    def __init__(self, seed: bytes = None):
        if seed is None:
            seed = os.urandom(32)
        elif len(seed) != 32:
            raise ValueError(f"Private seed must be 32 bytes, got {len(seed)}")
        
        self._seed = bytes(seed)
        self._c_key = None
        if _HAS_CRYPTOGRAPHY:
            try:
                self._c_key = _c_ed25519.Ed25519PrivateKey.from_private_bytes(self._seed)
                self._public_key = Ed25519PublicKey(self._c_key.public_key().public_bytes_raw())
            except Exception:
                self._c_key = None
                self._public_key = Ed25519PublicKey(_pure_publickey(self._seed))
        else:
            self._public_key = Ed25519PublicKey(_pure_publickey(self._seed))

    @classmethod
    def generate(cls) -> "Ed25519PrivateKey":
        return cls(os.urandom(32))

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._public_key

    def private_bytes(self) -> bytes:
        return self._seed

    def sign(self, message: bytes) -> bytes:
        """Signs a message and returns a 64-byte signature."""
        if self._c_key is not None:
            return self._c_key.sign(message)
        return _pure_sign(self._seed, self._public_key.public_bytes(), message)

    def to_hex(self) -> str:
        return self._seed.hex()

    @classmethod
    def from_hex(cls, hex_str: str) -> "Ed25519PrivateKey":
        return cls(bytes.fromhex(hex_str))
