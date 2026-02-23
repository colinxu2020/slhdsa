from pytest import raises

from slhdsa import SecretKey, PublicKey, sha2_128s


def test1():
    sec = SecretKey.from_pkcs('tests/fixtures/test_c_sec.bin')
    with raises(ValueError):
        SecretKey.from_pkcs('tests/fixtures/test_c_pub.bin')
    with raises(ValueError):
        PublicKey.from_pkcs('tests/fixtures/test_c_sec.bin')
    pub = PublicKey.from_pkcs('tests/fixtures/test_c_pub.bin')
    assert sec.pubkey == pub
    msg = open('tests/fixtures/test_c_msg.bin', 'rb').read()
    sig = open('tests/fixtures/test_c_sig.bin', 'rb').read()
    assert pub.verify_pure(msg, sig)
