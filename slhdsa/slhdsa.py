from dataclasses import dataclass

import slhdsa.lowlevel.slhdsa as lowlevel
from slhdsa.lowlevel.parameters import Parameter
import slhdsa.exception as exc


@dataclass
class PublicKey:
    key: tuple[bytes, bytes]
    par: Parameter

    def verify(self, msg: bytes, sig: bytes) -> bool:
        return lowlevel.verify(msg, sig, self.key, self.par)

    def digest(self) -> bytes:
        return b''.join(self.key)

    @classmethod
    def from_digest(cls, digest: bytes, par: Parameter) -> "PublicKey":
        if len(digest) != 2 * par.n:
            raise exc.SLHDSAKeyException('Wrong digest length')
        return cls((digest[:par.n], digest[par.n:]), par)

    def __str__(self) -> str:
        return f'<SLHDSA Public Key: {self.digest().hex()}>'


@dataclass
class SecretKey:
    key: tuple[bytes, bytes, bytes, bytes]
    par: Parameter

    def __init__(self, key: tuple[bytes, bytes, bytes, bytes], par: Parameter):
        if not lowlevel.validate_secretkey(key, par):
            raise exc.SLHDSAKeyException("Invalid secret key")
        self.key = key
        self.par = par

    def sign(self, msg: bytes, randomize: bool = False) -> bytes:
        return lowlevel.sign(msg, self.key, self.par, randomize)

    def digest(self) -> bytes:
        return b''.join(self.key)

    @classmethod
    def from_digest(cls, digest: bytes, par: Parameter) -> "SecretKey":
        if len(digest) != 4 * par.n:
            raise exc.SLHDSAKeyException("Wrong digest length")
        return cls((digest[:par.n], digest[par.n:par.n*2], digest[par.n*2:par.n*3], digest[par.n*3:]), par)

    def __str__(self) -> str:
        return f'<SLHDSA Secret Key: {self.digest().hex()}>'


@dataclass
class KeyPair:
    pub: PublicKey
    sec: SecretKey

    def verify(self, msg: bytes, sig: bytes) -> bool:
        return self.pub.verify(msg, sig)

    def sign(self, msg: bytes, randomize: bool = False) -> bytes:
        return self.sec.sign(msg, randomize)

    @classmethod
    def gen(cls, par: Parameter) -> "KeyPair":
        sec, pub = lowlevel.keygen(par)
        return cls(PublicKey(pub, par), SecretKey(sec, par))

    def digest(self) -> bytes:
        return self.pub.digest() + self.sec.digest()

    @classmethod
    def from_digest(cls, digest: bytes, par: Parameter) -> "KeyPair":
        return cls(PublicKey.from_digest(digest[:par.n*2], par), SecretKey.from_digest(digest[par.n*2:], par))
