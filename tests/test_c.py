import base64
import subprocess
import shutil
from pathlib import Path
from typing import Annotated

import pytest

import slhdsa.asn as asn
import slhdsa.asn.schema as schema
from slhdsa import KeyPair, SecretKey, sha2_128s
from slhdsa.slhdsa import AlgorithmIdentifier, PrivateKeyInfo, PublicKey


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


def test_length_and_tlv_error_paths():
    with pytest.raises(ValueError):
        schema._read_length(b"", 0)
    with pytest.raises(ValueError):
        schema._read_length(b"\x80", 0)
    with pytest.raises(ValueError):
        schema._read_length(b"\x82\x01", 0)
    with pytest.raises(ValueError):
        schema._read_tlv(b"", 0)
    with pytest.raises(ValueError):
        schema._read_tlv(b"\x02\x02\x01", 0)
    with pytest.raises(ValueError):
        schema._encode_length(-1)


def test_integer_descriptor_encoding_cases():
    with pytest.raises(TypeError):
        schema._INTEGER_DESCRIPTOR.encode("nope")
    neg_encoded = schema._INTEGER_DESCRIPTOR.encode(-1)
    neg_value, neg_end = schema._INTEGER_DESCRIPTOR.decode(neg_encoded, 0)
    assert neg_value == -1 and neg_end == len(neg_encoded)
    pos_encoded = schema._INTEGER_DESCRIPTOR.encode(0x7F)
    pos_value, pos_end = schema._INTEGER_DESCRIPTOR.decode(pos_encoded, 0)
    assert pos_value == 0x7F and pos_end == len(pos_encoded)


def test_octet_string_descriptor_errors():
    with pytest.raises(TypeError):
        schema._OCTET_STRING_DESCRIPTOR.encode(123)
    with pytest.raises(ValueError):
        schema._OCTET_STRING_DESCRIPTOR.decode(b"\x05\x00", 0)


def test_object_identifier_validation_and_decode_errors():
    with pytest.raises(TypeError):
        schema._OBJECT_IDENTIFIER_DESCRIPTOR.encode([1, 2])
    with pytest.raises(ValueError):
        schema._OBJECT_IDENTIFIER_DESCRIPTOR.encode((1,))
    with pytest.raises(ValueError):
        schema._OBJECT_IDENTIFIER_DESCRIPTOR.encode((3, 0))
    with pytest.raises(ValueError):
        schema._OBJECT_IDENTIFIER_DESCRIPTOR.encode((1, -1))
    with pytest.raises(ValueError):
        schema._OBJECT_IDENTIFIER_DESCRIPTOR.encode((1, 40))
    with pytest.raises(TypeError):
        schema._OBJECT_IDENTIFIER_DESCRIPTOR.encode((1, 2, "x"))
    with pytest.raises(ValueError):
        schema._OBJECT_IDENTIFIER_DESCRIPTOR.decode(b"\x02\x01\x00", 0)
    with pytest.raises(ValueError):
        schema._OBJECT_IDENTIFIER_DESCRIPTOR.decode(b"\x06\x00", 0)
    with pytest.raises(ValueError):
        schema._OBJECT_IDENTIFIER_DESCRIPTOR.decode(b"\x06\x02\x2a\x81", 0)
    with pytest.raises(ValueError):
        schema._encode_base128(-1)
    assert schema._encode_base128(0) == b"\x00"


def test_sequence_descriptor_prepare_and_build_variants():
    seq = schema._SequenceDescriptor((schema._INTEGER_DESCRIPTOR,), tuple)
    with pytest.raises(ValueError):
        seq.encode((1, 2))
    with pytest.raises(TypeError):
        seq.encode(object())
    with pytest.raises(ValueError):
        seq.decode(b"\x31\x00", 0)
    assert seq._build_python_value([9]) == (9,)
    seq_list = schema._SequenceDescriptor((schema._INTEGER_DESCRIPTOR,), list)
    assert seq_list._build_python_value([7]) == [7]
    seq_set = schema._SequenceDescriptor((schema._INTEGER_DESCRIPTOR,), set)
    assert seq_set._build_python_value([5]) == {5}
    seq_callable = schema._SequenceDescriptor((schema._INTEGER_DESCRIPTOR,), lambda v: {"values": tuple(v)})
    assert seq_callable._build_python_value([4]) == {"values": (4,)}


class Pair(schema.Schema):
    first: asn.Integer
    second: asn.Integer


def test_schema_field_descriptor_and_prepare_iterable():
    descriptor = schema._SequenceDescriptor((schema._INTEGER_DESCRIPTOR, schema._INTEGER_DESCRIPTOR), Pair)
    built = descriptor._build_python_value([1, 2])
    assert isinstance(built, Pair)
    assert descriptor._prepare_iterable(built) == (1, 2)
    with pytest.raises(TypeError):
        schema._SchemaFieldDescriptor(Pair).encode("nope")


def test_schema_construction_errors_and_repr():
    class TwoInts(schema.Schema):
        a: asn.Integer
        b: asn.Integer
    with pytest.raises(TypeError):
        TwoInts(1, b=2)
    with pytest.raises(TypeError):
        TwoInts(1)
    with pytest.raises(TypeError):
        TwoInts(a=1)
    with pytest.raises(TypeError):
        TwoInts(a=1, b=2, c=3)
    obj = TwoInts(a=1, b=2)
    assert "TwoInts" in repr(obj)


def test_sequence_annotation_must_have_children():
    with pytest.raises(TypeError):
        class _(asn.Schema):
            value: asn.Sequence


def test_coercion_to_bytes_with_sequence_element_types():
    class BytePair(asn.Schema):
        payload: Annotated[tuple[bytes, bytes], asn.Sequence[asn.OctetString, asn.OctetString]]
    original = BytePair((asn.OctetString(b"a"), asn.OctetString(b"b")))
    decoded = BytePair.loads(original.dumps())
    assert decoded.payload == (b"a", b"b")


def test_openssl_interop(tmp_path: Path):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl not available")
    priv_path = tmp_path / "slhdsa.pem"
    pub_path = tmp_path / "slhdsa_pub.pem"
    msg_path = tmp_path / "msg.bin"
    msg_path.write_bytes(b"openssl-interop")
    try:
        subprocess.run(
            [openssl, "genpkey", "-algorithm", "slh-dsa-sha2-128s", "-out", str(priv_path)],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode(errors="ignore") if exc.stderr else ""
        pytest.skip(f"openssl genpkey unsupported: {stderr}")
    subprocess.run([openssl, "pkey", "-in", str(priv_path), "-pubout", "-out", str(pub_path)], check=True, capture_output=True)
    sk = SecretKey.from_pkcs(str(priv_path))
    assert sk.par is sha2_128s
    pub = PublicKey((sk.key[2], sk.key[3]), sk.par)
    sig = sk.sign(msg_path.read_bytes())
    sig_path = tmp_path / "libsig.bin"
    sig_path.write_bytes(sig)
    verify_run = subprocess.run(
        [
            openssl,
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(pub_path),
            "-sigfile",
            str(sig_path),
            "-rawin",
            "-in",
            str(msg_path),
        ],
        capture_output=True,
    )
    if verify_run.returncode != 0:
        stderr = verify_run.stderr.decode(errors="ignore") if verify_run.stderr else ""
        pytest.fail(f"OpenSSL failed verifying library signature: {stderr}")
    ossig_path = tmp_path / "ossig.bin"
    subprocess.run(
        [openssl, "pkeyutl", "-sign", "-inkey", str(priv_path), "-rawin", "-in", str(msg_path), "-out", str(ossig_path)],
        check=True,
        capture_output=True,
    )
    ossig = ossig_path.read_bytes()
    assert pub.verify(msg_path.read_bytes(), ossig)
