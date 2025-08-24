from hashlib import sha256, sha512

from pytest import raises

from slhdsa import KeyPair, shake_256s
from slhdsa.lowlevel.fors import FORS
from slhdsa.lowlevel.xmss import XMSS
from slhdsa.lowlevel.addresses import FORSTreeAddress, Address
import slhdsa.lowlevel.parameters


def test1():
    kp = KeyPair.gen(shake_256s)
    assert str(kp.sec) == f'<SLHDSA Secret Key: {kp.sec.digest().hex()}>'
    assert str(kp.pub) == f'<SLHDSA Public Key: {kp.pub.digest().hex()}>'
    
def test2():
    assert FORS(shake_256s).node(b"", 0, shake_256s.a+1, b"", FORSTreeAddress(0, 0)) == b""
    assert XMSS(shake_256s).node(b"", 0, shake_256s.h_m+1, b"", Address(0, 0)) == b""
    
def test3():
    with raises(ValueError):
        slhdsa.lowlevel.parameters.mgf1_sha256(b"", (sha256().digest_size << 32) + 1)
    with raises(ValueError):
        slhdsa.lowlevel.parameters.mgf1_sha512(b"", (sha512().digest_size << 32) + 1)
        