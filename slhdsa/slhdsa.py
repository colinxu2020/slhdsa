from dataclasses import dataclass
from base64 import b64decode, b64encode
import hashlib
from typing import Callable, Optional

import slhdsa.lowlevel.slhdsa as lowlevel
import slhdsa.lowlevel.parameters
from slhdsa.lowlevel.parameters import Parameter
import slhdsa.exception as exc
import slhdsa.asn.schema


HASH_ALGORITHMS_OID_BY_FUNCTION = {
    hashlib.sha256: 0x01,
    hashlib.sha512: 0x03,
    hashlib.shake_128: 0x0b,
    hashlib.shake_256: 0x0c
}
HASH_ALGORITHM_FUNCTION_BY_OID = {
    0x01: hashlib.sha256,
    0x03: hashlib.sha512,
    0x0b: hashlib.shake_128,
    0x0c: hashlib.shake_256
}
HASH_ALGORITHM_OID_PREFIX = b'\x06\t`\x86H\x01e\x03\x04\x02'
PARAMETER_BY_OID = {
    26: slhdsa.lowlevel.parameters.shake_128s,
    27: slhdsa.lowlevel.parameters.shake_128f,
    28: slhdsa.lowlevel.parameters.shake_192s,
    29: slhdsa.lowlevel.parameters.shake_192f,
    30: slhdsa.lowlevel.parameters.shake_256s,
    31: slhdsa.lowlevel.parameters.shake_256f,
    20: slhdsa.lowlevel.parameters.sha2_128s,
    21: slhdsa.lowlevel.parameters.sha2_128f,
    22: slhdsa.lowlevel.parameters.sha2_192s,
    23: slhdsa.lowlevel.parameters.sha2_192f,
    24: slhdsa.lowlevel.parameters.sha2_256s,
    25: slhdsa.lowlevel.parameters.sha2_256f,
}

class AlgorithmIdentifier(slhdsa.asn.schema.Schema):
    oid: slhdsa.asn.ObjectIdentifier


class PrivateKeyInfo(slhdsa.asn.schema.Schema):
    version: slhdsa.asn.Integer
    algorithm: AlgorithmIdentifier
    private_key: slhdsa.asn.OctetString


class PublicKeyInfo(slhdsa.asn.schema.Schema):
    algorithm: AlgorithmIdentifier
    public_key: slhdsa.asn.BitString


@dataclass
class PublicKey:
    key: tuple[bytes, bytes]
    par: Parameter

    def verify(self, msg: bytes, sig: bytes) -> bool:
        """
        Verifies a Bare SLH-DSA signature.
        This method is not recommended for new applications.
        It implements the SLH-DSA Initial Draft rather than the final specification.
        While there are no security issues with this version, it may cause interoperability problems with other applications.
        """
        return lowlevel.verify(msg, sig, self.key, self.par)

    def verify_pure(self, msg: bytes, sig: bytes, ctx: bytes = b'') -> bool:
        """
        Verifies a Pure SLH-DSA signature.
        In most cases, we recommend that new applications use this API, which fully complies with the final version of the FIPS 205 specification.
        """
        if len(ctx) > 255:
            raise ValueError("Context too long")
        msg = b'\x00' + bytes([len(ctx)]) + ctx + msg
        return lowlevel.verify(msg, sig, self.key, self.par)

    def verify_hash(self, msg: bytes, sig: bytes, ctx: bytes = b'', prehash: Optional[Callable[[bytes], bytes]] = None) -> bool:
        """
        Verifies a Pre-hash SLH-DSA signature.
        We recommend this API for applications that need to sign large payloads or
        streaming data. This API fully complies with the final version of the FIPS 205
        specification. If you don't need to so, please refer to :func:`verify_pure` instead.
        If you want to use your own pre-hash function, you can pass it to the ``prehash`` parameter.
        Note that your function shall return a byte string contains the Object ID of your hash function followed by the actually hash.
        The hash function is automatically determined by the security category of the parameter otherwise.
        """
        if len(ctx) > 255:
            raise ValueError("Context too long")
        par = self.par
        if prehash is None:
            if par.objectid[-1] in (20, 21):
                def prehash(data: bytes) -> bytes:
                    return (HASH_ALGORITHM_OID_PREFIX + bytes([HASH_ALGORITHMS_OID_BY_FUNCTION[hashlib.sha256]])+
                            hashlib.sha256(data).digest())
            elif par.objectid[-1] in (22, 23, 24, 25):
                def prehash(data: bytes) -> bytes:
                    return (HASH_ALGORITHM_OID_PREFIX + bytes([HASH_ALGORITHMS_OID_BY_FUNCTION[hashlib.sha512]])+
                            hashlib.sha512(data).digest())
            elif par.objectid[-1] in (26, 27):
                def prehash(data: bytes) -> bytes:
                    return (HASH_ALGORITHM_OID_PREFIX + bytes([HASH_ALGORITHMS_OID_BY_FUNCTION[hashlib.shake_128]])+
                            hashlib.shake_128(data).digest(16))
            elif par.objectid[-1] in (28, 29, 30, 31):
                def prehash(data: bytes) -> bytes:
                    return (HASH_ALGORITHM_OID_PREFIX + bytes([HASH_ALGORITHMS_OID_BY_FUNCTION[hashlib.shake_256]])+
                            hashlib.shake_256(data).digest(32))
            else:
                assert False
        msg = b'\x01' + bytes([len(ctx)]) + ctx + prehash(msg)
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

    @classmethod
    def from_pkcs(cls, filename: str) -> "PublicKey":
        with open(filename, 'r') as fp:
            pubkey = [i[:-1] for i in fp]
        while pubkey[-1] == '':
            del pubkey[-1]
        if pubkey[0] != '-----BEGIN PUBLIC KEY-----' or pubkey[-1] != '-----END PUBLIC KEY-----':
            raise ValueError("Invalid PKCS Key")
        structure = PublicKeyInfo.loads(b64decode((''.join(pubkey[1:-1])).encode()))
        oid = structure.algorithm.oid
        digest = bytes(structure.public_key)
        if oid[:8] != (2, 16, 840, 1, 101, 3, 4, 3) or oid[8] < 20 or oid[8] > 31:
            raise ValueError("Non-SLHDSA Key Found")
        return cls.from_digest(digest, PARAMETER_BY_OID[oid[8]])

    def to_pkcs(self, filename: str) -> None:
        structure = PublicKeyInfo(
            algorithm=AlgorithmIdentifier(oid=self.par.objectid),
            public_key=slhdsa.asn.BitString(self.digest()),
        )
        crt = b64encode(structure.dumps()).decode()
        with open(filename, 'w') as fp:
            fp.write('-----BEGIN PUBLIC KEY-----\n')
            for i in range((len(crt) + 63) // 64):
                fp.write(crt[i*64:(i+1)*64])
                fp.write('\n')
            fp.write('-----END PUBLIC KEY-----\n')


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
        """
        Generates a Bare SLH-DSA signature.
        This method is not recommended for new applications.
        It implements the SLH-DSA Initial Draft rather than the final specification.
        While there are no security issues with this version, it may cause interoperability problems with other applications.
        """
        return lowlevel.sign(msg, self.key, self.par, randomize)

    def sign_pure(self, msg: bytes, randomize: bool = False, ctx: bytes = b'') -> bytes:
        """
        Generates a Pure SLH-DSA signature.
        In most cases, we recommend that new applications use this API, which fully complies with the final version of the FIPS 205 specification.
        """
        if len(ctx) > 255:
            raise ValueError("Context too long")
        msg = b'\x00' + bytes([len(ctx)]) + ctx + msg
        return lowlevel.sign(msg, self.key, self.par, randomize)

    def sign_hash(self, msg: bytes, randomize: bool = False, ctx: bytes = b'', prehash: Optional[Callable[[bytes], bytes]] = None) -> bytes:
        """
        Generates a Pre-hash SLH-DSA signature.
        We recommend this API for applications that need to sign large payloads or
        streaming data. This API fully complies with the final version of the FIPS 205
        specification. If you don't need so, please refer to :func:`sign_pure` instead.
        If you want to use your own pre-hash function, you can pass it to the ``prehash`` parameter.
        Note that your function shall return a byte string contains the Object ID of your hash function followed by the actually hash.
        The hash function is automatically determined by the security category of the parameter otherwise.
        """
        if len(ctx) > 255:
            raise ValueError("Context too long")
        if prehash is None:
            if self.par.objectid[-1] in (20, 21):
                def prehash(data: bytes) -> bytes:
                    return (HASH_ALGORITHM_OID_PREFIX + bytes([HASH_ALGORITHMS_OID_BY_FUNCTION[hashlib.sha256]])+
                            hashlib.sha256(data).digest())
            elif self.par.objectid[-1] in (22, 23, 24, 25):
                def prehash(data: bytes) -> bytes:
                    return (HASH_ALGORITHM_OID_PREFIX + bytes([HASH_ALGORITHMS_OID_BY_FUNCTION[hashlib.sha512]])+
                            hashlib.sha512(data).digest())
            elif self.par.objectid[-1] in (26, 27):
                def prehash(data: bytes) -> bytes:
                    return (HASH_ALGORITHM_OID_PREFIX + bytes([HASH_ALGORITHMS_OID_BY_FUNCTION[hashlib.shake_128]])+
                            hashlib.shake_128(data).digest(16))
            elif self.par.objectid[-1] in (28, 29, 30, 31):
                def prehash(data: bytes) -> bytes:
                    return (HASH_ALGORITHM_OID_PREFIX + bytes([HASH_ALGORITHMS_OID_BY_FUNCTION[hashlib.shake_256]])+
                            hashlib.shake_256(data).digest(32))
            else:
                assert False
        msg = b'\x01' + bytes([len(ctx)]) + ctx + prehash(msg)
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
        return cls.from_digest(digest, PARAMETER_BY_OID[oid[8]])
        
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

    @property
    def pubkey(self) -> PublicKey:
        return PublicKey((self.key[2], self.key[3]), self.par)

    @property
    def keypair(self) -> "KeyPair":
        return KeyPair(self.pubkey, self)


@dataclass
class KeyPair:
    pub: PublicKey
    sec: SecretKey

    def verify(self, msg: bytes, sig: bytes) -> bool:
        """
        Verifies a Bare SLH-DSA signature.
        This method is not recommended for new applications.
        It implements the SLH-DSA Initial Draft rather than the final specification.
        While there are no security issues with this version, it may cause interoperability problems with other applications.
        """
        return self.pub.verify(msg, sig)

    def verify_pure(self, msg: bytes, sig: bytes, ctx: bytes = b'') -> bool:
        """
        Verifies a Pure SLH-DSA signature.
        In most cases, we recommend that new applications use this API, which fully complies with the final version of the FIPS 205 specification.
        """
        if len(ctx) > 255:
            raise ValueError("Context too long")
        msg = b'\x00' + bytes([len(ctx)]) + ctx + msg
        return self.pub.verify(msg, sig)

    def verify_hash(self, msg: bytes, sig: bytes, ctx: bytes = b'', prehash: Optional[Callable[[bytes], bytes]] = None) -> bool:
        """
        Verifies a Pre-hash SLH-DSA signature.
        We recommend this API for applications that need to sign large payloads or
        streaming data. This API fully complies with the final version of the FIPS 205
        specification. If you don't need to so, please refer to :func:`verify_pure` instead.
        If you want to use your own pre-hash function, you can pass it to the ``prehash`` parameter.
        Note that your function shall return a byte string contains the Object ID of your hash function followed by the actually hash.
        The hash function is automatically determined by the security category of the parameter otherwise.
        """
        if len(ctx) > 255:
            raise ValueError("Context too long")
        par = self.sec.par
        if prehash is None:
            if par.objectid[-1] in (20, 21):
                def prehash(data: bytes) -> bytes:
                    return (HASH_ALGORITHM_OID_PREFIX + bytes([HASH_ALGORITHMS_OID_BY_FUNCTION[hashlib.sha256]])+
                            hashlib.sha256(data).digest())
            elif par.objectid[-1] in (22, 23, 24, 25):
                def prehash(data: bytes) -> bytes:
                    return (HASH_ALGORITHM_OID_PREFIX + bytes([HASH_ALGORITHMS_OID_BY_FUNCTION[hashlib.sha512]])+
                            hashlib.sha512(data).digest())
            elif par.objectid[-1] in (26, 27):
                def prehash(data: bytes) -> bytes:
                    return (HASH_ALGORITHM_OID_PREFIX + bytes([HASH_ALGORITHMS_OID_BY_FUNCTION[hashlib.shake_128]])+
                            hashlib.shake_128(data).digest(16))
            elif par.objectid[-1] in (28, 29, 30, 31):
                def prehash(data: bytes) -> bytes:
                    return (HASH_ALGORITHM_OID_PREFIX + bytes([HASH_ALGORITHMS_OID_BY_FUNCTION[hashlib.shake_256]])+
                            hashlib.shake_256(data).digest(32))
            else:
                assert False
        msg = b'\x01' + bytes([len(ctx)]) + ctx + prehash(msg)
        return self.pub.verify(msg, sig)

    def sign(self, msg: bytes, randomize: bool = False) -> bytes:
        """
        Generates a Bare SLH-DSA signature.
        This method is not recommended for new applications.
        It implements the SLH-DSA Initial Draft rather than the final specification.
        While there are no security issues with this version, it may cause interoperability problems with other applications.
        """
        return self.sec.sign(msg, randomize)

    def sign_pure(self, msg: bytes, randomize: bool = False, ctx: bytes = b'') -> bytes:
        """
        Generates a Pure SLH-DSA signature.
        In most cases, we recommend that new applications use this API, which fully complies with the final version of the FIPS 205 specification.
        """
        return self.sec.sign_pure(msg, randomize, ctx)

    def sign_hash(self, msg: bytes, randomize: bool = False, ctx: bytes = b'', prehash: Optional[Callable[[bytes], bytes]] = None) -> bytes:
        """
        Generates a Pre-hash SLH-DSA signature.
        We recommend this API for applications that need to sign large payloads or
        streaming data. This API fully complies with the final version of the FIPS 205
        specification. If you don't need to so, please refer to :func:`sign_pure` instead.
        If you want to use your own pre-hash function, you can pass it to the ``prehash`` parameter.
        Note that your function shall return a byte string contains the Object ID of your hash function followed by the actually hash.
        The hash function is automatically determined by the security category of the parameter otherwise.
        """
        return self.sec.sign_hash(msg, randomize, ctx, prehash)

    @classmethod
    def gen(cls, par: Parameter) -> "KeyPair":
        sec, pub = lowlevel.keygen(par)
        return cls(PublicKey(pub, par), SecretKey(sec, par))

    def digest(self) -> bytes:
        return self.pub.digest() + self.sec.digest()

    @classmethod
    def from_digest(cls, digest: bytes, par: Parameter) -> "KeyPair":
        return cls(PublicKey.from_digest(digest[:par.n*2], par), SecretKey.from_digest(digest[par.n*2:], par))
