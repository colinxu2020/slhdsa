from dataclasses import dataclass
from typing import Callable
from hashlib import shake_256, sha256, sha512
from hmac import digest as hmac_digest

from slhdsa.lowlevel.addresses import Address
from slhdsa.lowlevel._utils import trunc, compact_address


@dataclass
class Parameter:
    n: int
    h: int
    d: int
    h_m: int
    a: int
    k: int
    lgw: int
    m: int
    Hmsg: Callable[[bytes, bytes, bytes, bytes], bytes]
    PRF: Callable[[bytes, bytes, Address], bytes]
    PRFmsg: Callable[[bytes, bytes, bytes], bytes]
    F: Callable[[bytes, Address, bytes], bytes]
    H: Callable[[bytes, Address, bytes], bytes]
    Tl: Callable[[bytes, Address, bytes], bytes]


# Declare the shake parameters defined in fIPS205
def shake_functions(n: int, m: int) -> tuple[Callable[..., bytes], ...]:
    def h_msg(r: bytes, pk_seed: bytes, pk_root: bytes, msg: bytes) -> bytes:
        return shake_256(r + pk_seed + pk_root + msg).digest(m)

    def prf(pk_seed: bytes, sk_seed: bytes, address: Address) -> bytes:
        return shake_256(pk_seed +  address.to_bytes() + sk_seed).digest(n)

    def prf_msg(sk_prf: bytes, opt_rand: bytes, msg: bytes) -> bytes:
        return shake_256(sk_prf + opt_rand + msg).digest(n)

    def f(pk_seed: bytes, address: Address, msg1: bytes) -> bytes:
        return shake_256(pk_seed + address.to_bytes() + msg1).digest(n)

    def h(pk_seed: bytes, address: Address, msg2: bytes) -> bytes:
        return shake_256(pk_seed + address.to_bytes() + msg2).digest(n)

    def t_l(pk_seed: bytes, address: Address, msgl: bytes) -> bytes:
        return shake_256(pk_seed + address.to_bytes() + msgl).digest(n)

    return h_msg, prf, prf_msg, f, h, t_l


shake_128s: Parameter = Parameter(16, 63, 7, 9, 12, 14, 4, 30, *shake_functions(16, 30))
shake_128f: Parameter = Parameter(16, 66, 22, 3, 6, 33, 4, 34, *shake_functions(16, 35))
shake_192s: Parameter = Parameter(24, 63, 7, 9, 14, 17, 4, 39, *shake_functions(24, 39))
shake_192f: Parameter = Parameter(24, 66, 22, 3, 8, 33, 4, 42, *shake_functions(24, 42))
shake_256s: Parameter = Parameter(32, 64, 8, 8, 14, 22, 4, 47, *shake_functions(32, 47))
shake_256f: Parameter = Parameter(32, 68, 17, 4, 9, 35, 4, 49, *shake_functions(32, 49))


# Declares the sha256 parameters defined in fIPS205
def mgf1_sha256(seed: bytes, length: int) -> bytes:  # based on https://en.wikipedia.org/wiki/mask_generation_function
    hash_len = sha256().digest_size
    if length > (hash_len << 32):
        raise ValueError("Length Too Big")
    result = b""
    counter = 0
    while len(result) < length:
        byte = int.to_bytes(counter, 4, "big")
        result += sha256(seed + byte).digest()
        counter += 1
    return result[:length]


def mgf1_sha512(seed: bytes, length: int) -> bytes:  # based on https://en.wikipedia.org/wiki/mask_generation_function
    hash_len = sha512().digest_size
    if length > (hash_len << 32):
        raise ValueError("Length Too Big")
    result = b""
    counter = 0
    while len(result) < length:
        byte = int.to_bytes(counter, 4, "big")
        result += sha512(seed + byte).digest()
        counter += 1
    return result[:length]


def sha2_1_functions(n: int, m: int) -> tuple[Callable[..., bytes], ...]:
    def h_msg(r: bytes, pk_seed: bytes, pk_root: bytes, msg: bytes) -> bytes:
        return mgf1_sha256(r + pk_seed + sha256(r + pk_seed + pk_root + msg).digest(), m)

    def prf(pk_seed: bytes, sk_seed: bytes, address: Address) -> bytes:
        return trunc(sha256(pk_seed + b"\x00" * (64 - n) + compact_address(address.to_bytes()) + sk_seed).digest(), n)

    def prf_msg(sk_prf: bytes, opt_rand: bytes, msg: bytes) -> bytes:
        return trunc(hmac_digest(sk_prf, opt_rand + msg, "sha256"), n)

    def f(pk_seed: bytes, address: Address, msg1: bytes) -> bytes:
        return trunc(sha256(pk_seed + b"\x00" * (64 - n) + compact_address(address.to_bytes()) + msg1).digest(), n)

    def h(pk_seed: bytes, address: Address, msg2: bytes) -> bytes:
        return trunc(sha256(pk_seed + b"\x00" * (64 - n) + compact_address(address.to_bytes()) + msg2).digest(), n)

    def t_l(pk_seed: bytes, address: Address, msgl: bytes) -> bytes:
        return trunc(sha256(pk_seed + b"\x00" * (64 - n) + compact_address(address.to_bytes()) + msgl).digest(), n)

    return h_msg, prf, prf_msg, f, h, t_l


def sha2_35_functions(n: int, m: int) -> tuple[Callable[..., bytes], ...]:
    def h_msg(r: bytes, pk_seed: bytes, pk_root: bytes, msg: bytes) -> bytes:
        return mgf1_sha512(r + pk_seed + sha512(r + pk_seed + pk_root + msg).digest(), m)

    def prf(pk_seed: bytes, sk_seed: bytes, address: Address) -> bytes:
        return trunc(sha256(pk_seed + b"\x00" * (64 - n) + compact_address(address.to_bytes()) + sk_seed).digest(), n)

    def prf_msg(sk_prf: bytes, opt_rand: bytes, msg: bytes) -> bytes:
        return trunc(hmac_digest(sk_prf, opt_rand + msg, "sha512"), n)

    def f(pk_seed: bytes, address: Address, msg1: bytes) -> bytes:
        return trunc(sha256(pk_seed + b"\x00" * (64 - n) + compact_address(address.to_bytes()) + msg1).digest(), n)

    def h(pk_seed: bytes, address: Address, msg2: bytes) -> bytes:
        return trunc(sha512(pk_seed + b"\x00" * (128 - n) + compact_address(address.to_bytes()) + msg2).digest(), n)

    def t_l(pk_seed: bytes, address: Address, msgl: bytes) -> bytes:
        return trunc(sha512(pk_seed + b"\x00" * (128 - n) + compact_address(address.to_bytes()) + msgl).digest(), n)

    return h_msg, prf, prf_msg, f, h, t_l


sha2_128s: Parameter = Parameter(16, 63, 7, 9, 12, 14, 4, 30, *sha2_1_functions(16, 30))
sha2_128f: Parameter = Parameter(16, 66, 22, 3, 6, 33, 4, 34, *sha2_1_functions(16, 35))
sha2_192s: Parameter = Parameter(24, 63, 7, 9, 14, 17, 4, 39, *sha2_35_functions(24, 39))
sha2_192f: Parameter = Parameter(24, 66, 22, 3, 8, 33, 4, 42, *sha2_35_functions(24, 42))
sha2_256s: Parameter = Parameter(32, 64, 8, 8, 14, 22, 4, 47, *sha2_35_functions(32, 47))
sha2_256f: Parameter = Parameter(32, 68, 17, 4, 9, 35, 4, 49, *sha2_35_functions(32, 49))