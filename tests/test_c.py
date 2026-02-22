import base64
from pathlib import Path

import pytest

import slhdsa.asn as asn
from slhdsa import KeyPair, SecretKey, sha2_128s
from slhdsa.slhdsa import AlgorithmIdentifier, PrivateKeyInfo


def test_integer_roundtrip():
    class SingleInt(asn.Schema):
        value: asn.Integer
    obj = SingleInt(123456789)
    encoded = obj.dumps()
    decoded = SingleInt.loads(encoded)
    assert decoded.value == obj.value


def test_octet_string_and_oid_roundtrip():
    class OctetOid(asn.Schema):
        data: asn.OctetString
        oid: asn.ObjectIdentifier
    payload = b"hello"
    oid_value = (1, 2, 840, 113549)
    obj = OctetOid(asn.OctetString(payload), oid_value)
    encoded = obj.dumps()
    decoded = OctetOid.loads(encoded)
    assert isinstance(decoded.data, asn.OctetString)
    assert bytes(decoded.data) == payload
    assert decoded.oid == oid_value


def test_sequence_error_paths():
    class SingleInt(asn.Schema):
        value: asn.Integer
    extra_payload = b"\x02\x01\x01\x02\x01\x02"
    with pytest.raises(ValueError):
        SingleInt.loads(b"\x30\x06" + extra_payload)
    with pytest.raises(ValueError):
        SingleInt.loads(b"\x30\x00")
    with pytest.raises(ValueError):
        SingleInt.loads(b"\x02\x01\x01")


def test_private_key_info_roundtrip_and_trailing_bytes():
    pkinfo = PrivateKeyInfo(
        version=0,
        algorithm=AlgorithmIdentifier(oid=sha2_128s.objectid),
        private_key=asn.OctetString(b"secret-bytes"),
    )
    encoded = pkinfo.dumps()
    decoded = PrivateKeyInfo.loads(encoded)
    assert decoded.version == 0
    assert decoded.algorithm.oid == sha2_128s.objectid
    assert bytes(decoded.private_key) == b"secret-bytes"
    with pytest.raises(ValueError):
        PrivateKeyInfo.loads(encoded + b"\x00")


def test_pkcs_roundtrip(tmp_path: Path):
    kp = KeyPair.gen(sha2_128s)
    pem_path = tmp_path / "slhdsa.pem"
    kp.sec.to_pkcs(str(pem_path))
    loaded = SecretKey.from_pkcs(str(pem_path))
    assert loaded.par is sha2_128s
    assert loaded.digest() == kp.sec.digest()
    msg = b"interop-check"
    sig = loaded.sign(msg)
    assert kp.pub.verify(msg, sig)


def test_pkcs_invalid_format(tmp_path: Path):
    pem_path = tmp_path / "bad.pem"
    pem_path.write_text("-----BEGIN OOPS-----\nAAAA\n-----END OOPS-----\n")
    with pytest.raises(ValueError):
        SecretKey.from_pkcs(str(pem_path))

