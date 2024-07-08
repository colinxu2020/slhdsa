from dataclasses import dataclass

import slhdsa.lowlevel.slhdsa as lowlevel
from slhdsa.lowlevel.parameters import Parameter
import slhdsa.exception as exc


@dataclass
class PublicKey:
    key: tuple[bytes, bytes]
    par: Parameter

    def verify(self, msg: bytes, sig: bytes) -> bool:
        try:
            return lowlevel.verify(msg, sig, self.key, self.par)
        except Exception:
            raise exc.SLHDSAVerifyException

    def digest(self) -> bytes:
        return b''.join(self.key)

    @classmethod
    def from_digest(cls, digest: bytes, par: Parameter) -> "PublicKey":
        return cls((digest[:par.n], digest[par.n:]), par)


@dataclass
class SecretKey:
    key: tuple[bytes, bytes, bytes, bytes]
    par: Parameter

    def sign(self, msg: bytes, randomize: bool = False) -> bytes:
        try:
            return lowlevel.sign(msg, self.key, self.par, randomize)
        except Exception:
            raise exc.SLHDSAVerifyException

    def digest(self) -> bytes:
        return b''.join(self.key)

    @classmethod
    def from_digest(cls, digest: bytes, par: Parameter) -> "SecretKey":
        return cls((digest[:par.n], digest[par.n:par.n*2], digest[par.n*2:par.n*3], digest[par.n*3:]), par)


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
    def from_digest(cls, digest: bytes, par: Parameter):
        return cls(PublicKey.from_digest(digest[:par.n*2], par), SecretKey.from_digest(digest[par.n*2:], par))
