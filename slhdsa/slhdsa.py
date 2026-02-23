from dataclasses import dataclass
from base64 import b64decode, b64encode

import slhdsa.lowlevel.slhdsa as lowlevel
import slhdsa.lowlevel.parameters
from slhdsa.lowlevel.parameters import Parameter
import slhdsa.exception as exc
import slhdsa.asn.schema


class AlgorithmIdentifier(slhdsa.asn.schema.Schema):
    oid: slhdsa.asn.ObjectIdentifier


class PrivateKeyInfo(slhdsa.asn.schema.Schema):
    version: slhdsa.asn.Integer
    algorithm: AlgorithmIdentifier
    private_key: slhdsa.asn.OctetString


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
    
    @classmethod
    def from_pkcs(cls, filename: str) -> "SecretKey":
        with open(filename, 'r') as fp:
            privkey = [i[:-1] for i in fp]
        while privkey[-1] == '':
            del privkey[-1]
        if privkey[0] != '-----BEGIN PRIVATE KEY-----' or privkey[-1] != '-----END PRIVATE KEY-----':
            raise ValueError("Invalid PKCS Key")
        structure = PrivateKeyInfo.loads(b64decode((''.join(privkey[1:-1])).encode()))
        if structure.version != 0:
            raise ValueError("Invalid PKCS Key")
        oid = structure.algorithm.oid
        digest = bytes(structure.private_key)
        if oid[:8] != (2, 16, 840, 1, 101, 3, 4, 3) or oid[8] < 20 or oid[8] > 31:
            raise ValueError("Non-SLHDSA Key Found")
        if oid[8] == 20:
            algo = slhdsa.lowlevel.parameters.sha2_128s
        if oid[8] == 21:
            algo = slhdsa.lowlevel.parameters.sha2_128f
        if oid[8] == 22:
            algo = slhdsa.lowlevel.parameters.sha2_192s
        if oid[8] == 23:
            algo = slhdsa.lowlevel.parameters.sha2_192f
        if oid[8] == 24:
            algo = slhdsa.lowlevel.parameters.sha2_256s
        if oid[8] == 25:
            algo = slhdsa.lowlevel.parameters.sha2_256f
        if oid[8] == 26:
            algo = slhdsa.lowlevel.parameters.shake_128s
        if oid[8] == 27:
            algo = slhdsa.lowlevel.parameters.shake_128f
        if oid[8] == 26:
            algo = slhdsa.lowlevel.parameters.shake_128s
        if oid[8] == 27:
            algo = slhdsa.lowlevel.parameters.shake_128f
        if oid[8] == 28:
            algo = slhdsa.lowlevel.parameters.shake_192s
        if oid[8] == 29:
            algo = slhdsa.lowlevel.parameters.shake_192f
        if oid[8] == 30:
            algo = slhdsa.lowlevel.parameters.shake_256s
        if oid[8] == 31:
            algo = slhdsa.lowlevel.parameters.shake_256f
        return cls.from_digest(digest, algo)
        
    def to_pkcs(self, filename: str) -> None:
        structure = PrivateKeyInfo(
            version=0,
            algorithm=AlgorithmIdentifier(oid=self.par.objectid),
            private_key=slhdsa.asn.OctetString(self.digest()),
        )
        crt = b64encode(structure.dumps()).decode()
        with open(filename, 'w') as fp:
            fp.write('-----BEGIN PRIVATE KEY-----\n')
            for i in range((len(crt) + 63) // 64):
                fp.write(crt[i*64:(i+1)*64])
                fp.write('\n')
            fp.write('-----END PRIVATE KEY-----\n')


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
