from typing import Callable, Union
from hashlib import shake_256, sha256, sha512
from hmac import digest as hmac_digest

from slhdsa.lowlevel.addresses import Address
from slhdsa.lowlevel._utils import trunc, compact_address


class Parameter:
    oid_no: int
    n: int
    h: int
    d: int
    h_m: int
    a: int
    k: int
    lgw: int
    m: int
    
    def __init__(self, oid_no: int, n: int, h: int, d: int, h_m: int, a: int, k: int, lgw: int, m: int):
        self.oid_no = oid_no
        self.n = n
        self.h = h
        self.d = d
        self.h_m = h_m
        self.a = a
        self.k = k
        self.lgw = lgw
        self.m = m

    @property
    def objectid(self) -> tuple[int, int, int, int, int, int, int, int, int]:
        return (2, 16, 840, 1, 101, 3, 4, 3, self.oid_no)

    def Hmsg(self, r: Union[bytes, memoryview], pk_seed: Union[bytes, memoryview], pk_root: Union[bytes, memoryview], msg: Union[bytes, memoryview]) -> bytes:
        raise NotImplementedError

    def PRF(self, pk_seed: Union[bytes, memoryview], sk_seed: Union[bytes, memoryview], address: Address) -> bytes:
        raise NotImplementedError

    def PRFmsg(self, sk_prf: Union[bytes, memoryview], opt_rand: Union[bytes, memoryview], msg: Union[bytes, memoryview]) -> bytes:
        raise NotImplementedError

    def F(self, pk_seed: Union[bytes, memoryview], address: Address, msg1: Union[bytes, memoryview]) -> bytes:
        raise NotImplementedError

    def H(self, pk_seed: Union[bytes, memoryview], address: Address, msg2: Union[bytes, memoryview]) -> bytes:
        raise NotImplementedError

    def Tl(self, pk_seed: Union[bytes, memoryview], address: Address, msgl: Union[bytes, memoryview]) -> bytes:
        raise NotImplementedError


class ShakeParameter(Parameter):
    def Hmsg(self, r: Union[bytes, memoryview], pk_seed: Union[bytes, memoryview], pk_root: Union[bytes, memoryview], msg: Union[bytes, memoryview]) -> bytes:
        ctx = shake_256()
        ctx.update(r)
        ctx.update(pk_seed)
        ctx.update(pk_root)
        ctx.update(msg)
        return ctx.digest(self.m)

    def PRF(self, pk_seed: Union[bytes, memoryview], sk_seed: Union[bytes, memoryview], address: Address) -> bytes:
        ctx = shake_256()
        ctx.update(pk_seed)
        ctx.update(address.to_bytes())
        ctx.update(sk_seed)
        return ctx.digest(self.n)

    def PRFmsg(self, sk_prf: Union[bytes, memoryview], opt_rand: Union[bytes, memoryview], msg: Union[bytes, memoryview]) -> bytes:
        ctx = shake_256()
        ctx.update(sk_prf)
        ctx.update(opt_rand)
        ctx.update(msg)
        return ctx.digest(self.n)

    def F(self, pk_seed: Union[bytes, memoryview], address: Address, msg1: Union[bytes, memoryview]) -> bytes:
        ctx = shake_256()
        ctx.update(pk_seed)
        ctx.update(address.to_bytes())
        ctx.update(msg1)
        return ctx.digest(self.n)

    def H(self, pk_seed: Union[bytes, memoryview], address: Address, msg2: Union[bytes, memoryview]) -> bytes:
        ctx = shake_256()
        ctx.update(pk_seed)
        ctx.update(address.to_bytes())
        ctx.update(msg2)
        return ctx.digest(self.n)

    def Tl(self, pk_seed: Union[bytes, memoryview], address: Address, msgl: Union[bytes, memoryview]) -> bytes:
        ctx = shake_256()
        ctx.update(pk_seed)
        ctx.update(address.to_bytes())
        ctx.update(msgl)
        return ctx.digest(self.n)


# Declares the sha256 parameters defined in fIPS205
def mgf1_sha256(seed: Union[bytes, memoryview], length: int) -> bytes:  # based on https://en.wikipedia.org/wiki/mask_generation_function
    hash_len = sha256().digest_size
    if length > (hash_len << 32):
        raise ValueError("Length Too Big")
    result = bytearray()
    counter = 0
    while len(result) < length:
        byte = int.to_bytes(counter, 4, "big")
        ctx = sha256()
        ctx.update(seed)
        ctx.update(byte)
        result.extend(ctx.digest())
        counter += 1
    return bytes(result[:length])


def mgf1_sha512(seed: Union[bytes, memoryview], length: int) -> bytes:  # based on https://en.wikipedia.org/wiki/mask_generation_function
    hash_len = sha512().digest_size
    if length > (hash_len << 32):
        raise ValueError("Length Too Big")
    result = bytearray()
    counter = 0
    while len(result) < length:
        byte = int.to_bytes(counter, 4, "big")
        ctx = sha512()
        ctx.update(seed)
        ctx.update(byte)
        result.extend(ctx.digest())
        counter += 1
    return bytes(result[:length])


class Sha2_1Parameter(Parameter):
    def Hmsg(self, r: Union[bytes, memoryview], pk_seed: Union[bytes, memoryview], pk_root: Union[bytes, memoryview], msg: Union[bytes, memoryview]) -> bytes:
        ctx_inner = sha256()
        ctx_inner.update(r)
        ctx_inner.update(pk_seed)
        ctx_inner.update(pk_root)
        ctx_inner.update(msg)
        
        ctx_outer = bytearray()
        ctx_outer.extend(r)
        ctx_outer.extend(pk_seed)
        ctx_outer.extend(ctx_inner.digest())
        return mgf1_sha256(memoryview(ctx_outer), self.m)

    def PRF(self, pk_seed: Union[bytes, memoryview], sk_seed: Union[bytes, memoryview], address: Address) -> bytes:
        ctx = sha256()
        ctx.update(pk_seed)
        ctx.update(b"\x00" * (64 - self.n))
        ctx.update(compact_address(address.to_bytes()))
        ctx.update(sk_seed)
        return trunc(ctx.digest(), self.n)

    def PRFmsg(self, sk_prf: Union[bytes, memoryview], opt_rand: Union[bytes, memoryview], msg: Union[bytes, memoryview]) -> bytes:
        buf = bytearray()
        buf.extend(opt_rand)
        buf.extend(msg)
        return trunc(hmac_digest(sk_prf, memoryview(buf), "sha256"), self.n)

    def F(self, pk_seed: Union[bytes, memoryview], address: Address, msg1: Union[bytes, memoryview]) -> bytes:
        ctx = sha256()
        ctx.update(pk_seed)
        ctx.update(b"\x00" * (64 - self.n))
        ctx.update(compact_address(address.to_bytes()))
        ctx.update(msg1)
        return trunc(ctx.digest(), self.n)

    def H(self, pk_seed: Union[bytes, memoryview], address: Address, msg2: Union[bytes, memoryview]) -> bytes:
        ctx = sha256()
        ctx.update(pk_seed)
        ctx.update(b"\x00" * (64 - self.n))
        ctx.update(compact_address(address.to_bytes()))
        ctx.update(msg2)
        return trunc(ctx.digest(), self.n)

    def Tl(self, pk_seed: Union[bytes, memoryview], address: Address, msgl: Union[bytes, memoryview]) -> bytes:
        ctx = sha256()
        ctx.update(pk_seed)
        ctx.update(b"\x00" * (64 - self.n))
        ctx.update(compact_address(address.to_bytes()))
        ctx.update(msgl)
        return trunc(ctx.digest(), self.n)


class Sha2_35Parameter(Parameter):
    def Hmsg(self, r: Union[bytes, memoryview], pk_seed: Union[bytes, memoryview], pk_root: Union[bytes, memoryview], msg: Union[bytes, memoryview]) -> bytes:
        ctx_inner = sha512()
        ctx_inner.update(r)
        ctx_inner.update(pk_seed)
        ctx_inner.update(pk_root)
        ctx_inner.update(msg)
        
        ctx_outer = bytearray()
        ctx_outer.extend(r)
        ctx_outer.extend(pk_seed)
        ctx_outer.extend(ctx_inner.digest())
        return mgf1_sha512(memoryview(ctx_outer), self.m)

    def PRF(self, pk_seed: Union[bytes, memoryview], sk_seed: Union[bytes, memoryview], address: Address) -> bytes:
        ctx = sha256()
        ctx.update(pk_seed)
        ctx.update(b"\x00" * (64 - self.n))
        ctx.update(compact_address(address.to_bytes()))
        ctx.update(sk_seed)
        return trunc(ctx.digest(), self.n)

    def PRFmsg(self, sk_prf: Union[bytes, memoryview], opt_rand: Union[bytes, memoryview], msg: Union[bytes, memoryview]) -> bytes:
        buf = bytearray()
        buf.extend(opt_rand)
        buf.extend(msg)
        return trunc(hmac_digest(sk_prf, memoryview(buf), "sha512"), self.n)

    def F(self, pk_seed: Union[bytes, memoryview], address: Address, msg1: Union[bytes, memoryview]) -> bytes:
        ctx = sha256()
        ctx.update(pk_seed)
        ctx.update(b"\x00" * (64 - self.n))
        ctx.update(compact_address(address.to_bytes()))
        ctx.update(msg1)
        return trunc(ctx.digest(), self.n)

    def H(self, pk_seed: Union[bytes, memoryview], address: Address, msg2: Union[bytes, memoryview]) -> bytes:
        ctx = sha512()
        ctx.update(pk_seed)
        ctx.update(b"\x00" * (128 - self.n))
        ctx.update(compact_address(address.to_bytes()))
        ctx.update(msg2)
        return trunc(ctx.digest(), self.n)

    def Tl(self, pk_seed: Union[bytes, memoryview], address: Address, msgl: Union[bytes, memoryview]) -> bytes:
        ctx = sha512()
        ctx.update(pk_seed)
        ctx.update(b"\x00" * (128 - self.n))
        ctx.update(compact_address(address.to_bytes()))
        ctx.update(msgl)
        return trunc(ctx.digest(), self.n)


shake_128s: Parameter = ShakeParameter(26, 16, 63, 7, 9, 12, 14, 4, 30)
shake_128f: Parameter = ShakeParameter(27, 16, 66, 22, 3, 6, 33, 4, 34)
shake_192s: Parameter = ShakeParameter(28, 24, 63, 7, 9, 14, 17, 4, 39)
shake_192f: Parameter = ShakeParameter(29, 24, 66, 22, 3, 8, 33, 4, 42)
shake_256s: Parameter = ShakeParameter(30, 32, 64, 8, 8, 14, 22, 4, 47)
shake_256f: Parameter = ShakeParameter(31, 32, 68, 17, 4, 9, 35, 4, 49)

sha2_128s: Parameter = Sha2_1Parameter(20, 16, 63, 7, 9, 12, 14, 4, 30)
sha2_128f: Parameter = Sha2_1Parameter(21, 16, 66, 22, 3, 6, 33, 4, 34)
sha2_192s: Parameter = Sha2_35Parameter(22, 24, 63, 7, 9, 14, 17, 4, 39)
sha2_192f: Parameter = Sha2_35Parameter(23, 24, 66, 22, 3, 8, 33, 4, 42)
sha2_256s: Parameter = Sha2_35Parameter(24, 32, 64, 8, 8, 14, 22, 4, 47)
sha2_256f: Parameter = Sha2_35Parameter(25, 32, 68, 17, 4, 9, 35, 4, 49)
