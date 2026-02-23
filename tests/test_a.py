from pathlib import Path
from random import randbytes, randint

from pytest import raises

from slhdsa import KeyPair, sha2_128s, sha2_128f, sha2_192s, sha2_192f, sha2_256s, sha2_256f
from slhdsa import shake_128s, shake_128f, shake_192s, shake_192f, shake_256s, shake_256f
from slhdsa import SLHDSAKeyException, PublicKey, SecretKey


def _for_all(judger):
    judger(sha2_128s)
    judger(sha2_128f)
    judger(sha2_192s)
    judger(sha2_192f)
    judger(sha2_256s)
    judger(sha2_256f)
    judger(shake_128s)
    judger(shake_128f)
    judger(shake_192s)
    judger(shake_192f)
    judger(shake_256s)
    judger(shake_256f)


def test1():
    def judge(para):
        kp = KeyPair.gen(para)
        msg = randbytes(100)
        sig1 = kp.sign(msg)
        sig2 = kp.sign(msg)
        assert kp.verify(msg, sig1) and sig1 == sig2
        sig3 = kp.sign(msg, True)
        sig4 = kp.sign(msg, True)
        assert kp.verify(msg, sig3) and kp.verify(msg, sig4) and sig3 != sig4
    _for_all(judge)

def test2():
    def judge(para):
        kp1 = KeyPair.gen(para)
        digest = kp1.digest()
        kp2 = KeyPair.from_digest(digest, para)
        assert kp1.sec.key == kp2.sec.key and kp1.pub.key == kp2.pub.key
    _for_all(judge)
def test3():
    def judge(para):
        kp = KeyPair.gen(para)
        sec = kp.sec
        pub = kp.pub
        assert len(sec.key) == 4 and len(sec.key[0])==len(sec.key[1])==len(sec.key[2])==len(sec.key[3]) == para.n
        assert len(pub.key) == 2 and len(pub.key[0]) == len(pub.key[1]) == para.n
    _for_all(judge)

def test4():
    kp = KeyPair.from_digest(open('tests/fixtures/test_a_key1.bin', 'rb').read(), sha2_128f)
    sig = open('tests/fixtures/test_a_sig1.bin', 'rb').read()
    assert kp.verify(b'a', sig)
    assert kp.sign(b'a') == sig
    kp = KeyPair.from_digest(open('tests/fixtures/test_a_key2.bin', 'rb').read(), shake_128f)
    sig = open('tests/fixtures/test_a_sig2.bin', 'rb').read()
    assert kp.verify(b'a', sig)
    assert kp.sign(b'a') == sig
    kp = KeyPair.from_digest(open('tests/fixtures/test_a_key3.bin', 'rb').read(), sha2_256s)
    sig = open('tests/fixtures/test_a_sig3.bin', 'rb').read()
    assert kp.verify(b'\x01\x02\x03\x04', sig)
    assert kp.sign(b'\x01\x02\x03\x04') == sig
    kp = KeyPair.from_digest(open('tests/fixtures/test_a_key4.bin', 'rb').read(), sha2_192f)
    sig = open('tests/fixtures/test_a_sig4.bin', 'rb').read()
    assert kp.verify(b'\x01\x02\x03\x04', sig)
    assert kp.sign(b'\x01\x02\x03\x04') == sig
    kp = KeyPair.from_digest(open('tests/fixtures/test_a_key5.bin', 'rb').read(), shake_256f)
    sig = open('tests/fixtures/test_a_sig5.bin', 'rb').read()
    assert kp.verify(b'\x01\x02\x03\x04', sig)
    assert kp.sign(b'\x01\x02\x03\x04') == sig
    kp = KeyPair.from_digest(open('tests/fixtures/test_a_key6.bin', 'rb').read(), shake_192s)
    sig = open('tests/fixtures/test_a_sig6.bin', 'rb').read()
    assert kp.verify(b'\x01\x02\x03\x04', sig)
    assert kp.sign(b'\x01\x02\x03\x04') == sig
    kp = KeyPair.from_digest(open('tests/fixtures/test_a_key7.bin', 'rb').read(), sha2_128s)
    sig = open('tests/fixtures/test_a_sig7.bin', 'rb').read()
    assert kp.verify(b'\x01\x02\x03\x04', sig)
    assert kp.sign(b'\x01\x02\x03\x04') == sig


def test5():
    def judge(para):
        kp = KeyPair.gen(para)
        msg = randbytes(100)
        sig = kp.sign(msg)
        assert not kp.verify(msg, randbytes(100))
        sig1 = sig
        for i in range(20):
            pos = randint(0, len(sig))
            sig1 = sig1[:pos] + randbytes(1) + sig1[pos+1:]
        assert not kp.verify(msg, sig1)
        sig2 = sig[:-10] + randbytes(10)
        assert not kp.verify(msg, sig2)
        sig3 = randbytes(10) + sig[10:]
        assert not kp.verify(msg, sig3)
    _for_all(judge)
    
def test6():
    def judge(para):
        pk = KeyPair.gen(para).pub.digest()[:-1]
        with raises(SLHDSAKeyException):
            PublicKey.from_digest(pk, para)
        sk = KeyPair.gen(para).sec.digest()
        newchar = chr((sk[-1]+1)%256).encode()
        sk = sk[:-1]
        with raises(SLHDSAKeyException):
            SecretKey.from_digest(sk, para)
        with raises(SLHDSAKeyException):
            SecretKey.from_digest(sk+newchar, para)
        kp = KeyPair.gen(para).digest()
        newchar = chr((kp[-1]+1)%256).encode()
        kp = kp[:-1]
        with raises(SLHDSAKeyException):
            KeyPair.from_digest(kp, para)
        with raises(SLHDSAKeyException):
            KeyPair.from_digest(kp+newchar, para)
    _for_all(judge)

def test7(tmp_path: Path) -> None:
    def judge(para):
        sec = KeyPair.gen(para).sec
        sec_path = tmp_path / 'sec.pem'
        sec.to_pkcs(sec_path.as_posix())
        assert SecretKey.from_pkcs(sec_path.as_posix()) == sec
    _for_all(judge)

def test8(tmp_path: Path) -> None:
    def judge(para):
        pub = KeyPair.gen(para).pub
        pub_path = tmp_path / 'pub.pem'
        pub.to_pkcs(pub_path.as_posix())
        assert PublicKey.from_pkcs(pub_path.as_posix()) == pub
    _for_all(judge)
