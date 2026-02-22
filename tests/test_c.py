from pathlib import Path
from typing import Annotated, Any, Tuple

import pytest

import slhdsa.asn as asn
import slhdsa.asn.schema as schema
from slhdsa import KeyPair, SecretKey, sha2_128s
from slhdsa.slhdsa import AlgorithmIdentifier, PrivateKeyInfo


def test_sequence_meta_single_parameter():
    annotated = asn.Sequence[asn.Integer]
    base, extras = schema._unpack_annotated(annotated)
    assert base is asn.Sequence
    assert extras and extras[0][0] is asn.Integer


def test_asn1type_not_implemented():
    instance = schema._ASN1Type()
    with pytest.raises(NotImplementedError):
        instance.decode(b"", 0)
    with pytest.raises(NotImplementedError):
        instance.encode(None)


def test_length_helpers_long_form():
    assert schema._read_length(b"\x81\x05", 0) == (5, 2)
    assert schema._encode_length(0x80) == b"\x81\x80"


def test_encode_integer_content_trimming_and_prefix():
    class IntWithBits(int):
        def __new__(cls, value: int, extra_bits: int = 0):
            obj = int.__new__(cls, value)
            obj.extra_bits = extra_bits
            return obj

        def bit_length(self):
            return super().bit_length() + self.extra_bits
    positive = IntWithBits(0x80, 8)
    assert schema._encode_integer_content(positive) == b"\x00\x80"
    mixed = IntWithBits(0x1234, 8)
    assert schema._encode_integer_content(mixed) == b"\x12\x34"
    negative = IntWithBits(-1, 8)
    assert schema._encode_integer_content(negative) == b"\xff"


def test_integer_descriptor_bad_tag():
    with pytest.raises(ValueError):
        schema._INTEGER_DESCRIPTOR.decode(b"\x04\x00", 0)


def test_octet_string_descriptor_byteslike():
    encoded = schema._OCTET_STRING_DESCRIPTOR.encode(bytearray(b"ab"))
    assert encoded.startswith(b"\x04\x02ab")


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
    seq_object = schema._SequenceDescriptor((schema._INTEGER_DESCRIPTOR,), object())
    assert seq_object._build_python_value([3]) == (3,)
    assert seq._prepare_iterable({1, 2}) and set(seq._prepare_iterable({1, 2})) == {1, 2}
    class IterableWrapper:
        def __iter__(self):
            yield 5
    assert seq._prepare_iterable(IterableWrapper()) == (5,)


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
    class Base(schema.Schema):
        a: asn.Integer
    class Child(Base):
        a: asn.OctetString
        b: asn.Integer
    child = Child(a=asn.OctetString(b"v"), b=3)
    assert isinstance(child.a, asn.OctetString)


def test_sequence_annotation_must_have_children():
    with pytest.raises(TypeError):
        class _(asn.Schema):
            value: asn.Sequence
    with pytest.raises(TypeError):
        schema._descriptor_from_annotation(asn.Sequence)


def test_sequence_element_helpers_and_coercion():
    class BytePair(asn.Schema):
        payload: Annotated[tuple[bytes, bytes], asn.Sequence[asn.OctetString, asn.OctetString]]
    original = BytePair((asn.OctetString(b"a"), asn.OctetString(b"b")))
    decoded = BytePair.loads(original.dumps())
    assert decoded.payload == (b"a", b"b")
    assert schema._extract_sequence_element_types(tuple) == ()
    assert schema._extract_sequence_element_types(Tuple) == ()
    assert schema._expected_type_for_index((int, Ellipsis), 0) is int
    assert schema._expected_type_for_index((int, Ellipsis), 3) is int
    assert schema._expected_type_for_index((str, Ellipsis, bytes), 1) is str
    assert schema._expected_type_for_index((bytes, Ellipsis), 5) is bytes
    assert schema._expected_type_for_index((int, str), 5) is None
    annotated = Annotated[int, "meta"]
    assert schema._strip_annotated(annotated) is int
    assert schema._coerce_value_to_python_type("x", Any) == "x"
    class EqualsAny:
        def __eq__(self, other):
            return other is Any
    assert schema._coerce_value_to_python_type("y", EqualsAny()) == "y"
    octet = asn.OctetString(b"data")
    assert schema._coerce_value_to_python_type(octet, bytes) == b"data"
    buf = bytearray(b"z")
    assert schema._coerce_value_to_python_type(buf, bytes) == b"z"
    assert schema._coerce_value_to_python_type("keep", bytes) == "keep"
    descriptor = schema._SequenceDescriptor((schema._INTEGER_DESCRIPTOR,), tuple)
    assert schema._normalize_python_type(123) is tuple


def test_descriptor_resolution_edges(monkeypatch):
    descriptor = schema._SequenceDescriptor((schema._INTEGER_DESCRIPTOR,), tuple)
    copied = schema._resolve_descriptor(descriptor, list, ())
    assert isinstance(copied, schema._SequenceDescriptor) and copied is not descriptor
    annotated_seq = Annotated[asn.Sequence, schema._INTEGER_DESCRIPTOR]
    assert isinstance(schema._resolve_descriptor(annotated_seq, tuple, ()), schema._SequenceDescriptor)
    annotated_int = Annotated[int, schema._INTEGER_DESCRIPTOR]
    assert schema._resolve_descriptor(annotated_int, tuple, ()) is schema._INTEGER_DESCRIPTOR
    assert schema._descriptor_from_base(tuple[int], tuple, ()) is None
    sentinel = object()
    original_get_origin = schema.get_origin
    original_get_args = schema.get_args
    monkeypatch.setattr(schema, "get_origin", lambda obj: Annotated if obj is sentinel else original_get_origin(obj))
    monkeypatch.setattr(schema, "get_args", lambda obj: (asn.Sequence,) if obj is sentinel else original_get_args(obj))
    with pytest.raises(TypeError):
        schema._resolve_descriptor(sentinel, tuple, ())


def test_schema_meta_missing_annotation(monkeypatch):
    monkeypatch.setattr(schema, "get_type_hints", lambda cls, include_extras=True: {})
    with pytest.raises(TypeError):
        class _Bad(schema.Schema):
            a: "missing"
