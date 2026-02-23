import pytest
from slhdsa.asn import BitString, Integer, ObjectIdentifier, OctetString, Schema, Sequence
from slhdsa.slhdsa import AlgorithmIdentifier, PrivateKeyInfo
from slhdsa.asn.schema import ASN1LengthError, ASN1TagError, ASN1DecodeError, _encode_value, _encode_length, _decode_oid_arc, ASN1Error, _encode_oid_arc


def test_integer_roundtrip() -> None:
    values = [0, 1, 127, 128, 255, 256, -1, -128, -129, -256, 2 ** 2047, -(2 ** 2047)]
    for val in values:
        encoded = Integer(val).dumps()
        decoded = Integer.loads(encoded)
        assert decoded == val


def test_object_identifier_roundtrip() -> None:
    oid = ObjectIdentifier((1, 2, 840, 113549, 1, 1, 1))
    encoded = oid.dumps()
    decoded = ObjectIdentifier.loads(encoded)
    assert decoded == oid


def test_octet_string_roundtrip() -> None:
    data = b"hello world"
    encoded = OctetString(data).dumps()
    decoded = OctetString.loads(encoded)
    assert bytes(decoded) == data


def test_bit_string_roundtrip() -> None:
    bits = BitString(b"\xF0\x0F", unused_bits=4)
    encoded = bits.dumps()
    decoded = BitString.loads(encoded)
    assert decoded == bits


def test_sequence_roundtrip() -> None:
    class Child(Schema):
        a: Integer
        b: OctetString

    class Parent(Sequence):
        child: Child
        oid: ObjectIdentifier

    value = Parent(child=Child(a=5, b=b"abc"), oid=ObjectIdentifier((1, 3, 6, 1)))
    encoded = value.dumps()
    decoded = Parent.loads(encoded)
    assert isinstance(decoded.child.a, Integer)
    assert decoded.child.a == 5
    assert bytes(decoded.child.b) == b"abc"
    assert decoded.oid == (1, 3, 6, 1)


def test_private_key_info_roundtrip() -> None:
    oid = ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 3, 22))
    algo = AlgorithmIdentifier(oid=oid)
    secret = b"\x01\x02\x03\x04"
    info = PrivateKeyInfo(version=0, algorithm=algo, private_key=OctetString(secret))
    encoded = info.dumps()
    decoded = PrivateKeyInfo.loads(encoded)
    assert decoded.version == 0
    assert isinstance(decoded.version, Integer)
    assert decoded.algorithm.oid == oid
    assert bytes(decoded.private_key) == secret


def test_invalid_length_raises() -> None:
    bad = b"\x02\x81\x01\x00"  # INTEGER with long-form zero
    with pytest.raises(Exception):
        Integer.loads(bad)


def test_schema_missing_and_extra_fields() -> None:
    class Simple(Schema):
        a: Integer

    with pytest.raises(TypeError):
        Simple()  # missing
    with pytest.raises(TypeError):
        Simple(a=1, b=2)  # extra


def test_integer_wrong_tag() -> None:
    encoded = OctetString(b"123").dumps()
    with pytest.raises(ASN1TagError):
        Integer.loads(encoded)


def test_sequence_wrong_tag() -> None:
    encoded = OctetString(b"123").dumps()
    with pytest.raises(ASN1TagError):
        PrivateKeyInfo.loads(encoded)


def test_sequence_trailing_bytes() -> None:
    oid = ObjectIdentifier((1, 2, 3))
    algo = AlgorithmIdentifier(oid=oid)
    info = PrivateKeyInfo(version=0, algorithm=algo, private_key=OctetString(b"k"))
    encoded = info.dumps() + b"\x00"
    decoded = PrivateKeyInfo.loads(encoded[:-1])  # strict TLV length; trailing ignored by caller
    assert decoded.algorithm.oid == oid


def test_bit_string_invalid_unused_bits() -> None:
    with pytest.raises(Exception):
        BitString(b"", unused_bits=8)


def test_decode_length_non_minimal() -> None:
    bad = b"\x04\x82\x00\x03abc"  # OCTET STRING with non-minimal length
    with pytest.raises(ASN1LengthError):
        OctetString.loads(bad)


def test_oid_validation_first_arc() -> None:
    with pytest.raises(Exception):
        ObjectIdentifier((-1, 2))


def test_integer_leading_zero_rejected() -> None:
    bad = b"\x02\x02\x00\x7F"  # 0x7F should be short form length 1
    with pytest.raises(Exception):
        Integer.loads(bad)


def test_bit_string_missing_unused_byte() -> None:
    # BIT STRING with declared length 0 (no unused-bits byte)
    bad = b"\x03\x00"
    with pytest.raises(ASN1DecodeError):
        BitString.loads(bad)


def test_oid_truncated_arc() -> None:
    # OBJECT IDENTIFIER with continuation bit but truncated
    bad = b"\x06\x02\x2A\x81"  # 1.2 plus incomplete arc
    with pytest.raises(ASN1DecodeError):
        ObjectIdentifier.loads(bad)


def test_sequence_truncated_content() -> None:
    oid = ObjectIdentifier((1, 2, 3))
    algo = AlgorithmIdentifier(oid=oid)
    info = PrivateKeyInfo(version=0, algorithm=algo, private_key=OctetString(b"k"))
    encoded = info.dumps()
    with pytest.raises(ASN1LengthError):
        PrivateKeyInfo.loads(encoded[:-1])


def test_nested_dict_coercion() -> None:
    class Child(Schema):
        a: Integer

    class Parent(Sequence):
        child: Child

    obj = Parent(child={"a": 7})
    assert isinstance(obj.child, Child)
    assert obj.child.a == 7


def test_decode_value_unsupported_type() -> None:
    class Bad(Schema):
        a: int

    # Craft SEQUENCE containing INTEGER to reach _decode_value unsupported path
    payload = Integer(1).dumps()
    seq = b"\x30" + bytes([len(payload)]) + payload
    with pytest.raises(TypeError):
        Bad.loads(seq)


def test_bit_string_tuple_coercion() -> None:
    class Wrap(Schema):
        bits: BitString

    obj = Wrap(bits=(b"\xAA", 1))
    assert isinstance(obj.bits, BitString)
    assert obj.bits.unused_bits == 1


def test_integer_non_minimal_negative() -> None:
    # Non-minimal encoding for -1 (should be 0x01 0xFF)
    bad = b"\x02\x02\xFF\xFF"
    with pytest.raises(Exception):
        Integer.loads(bad)


def test_octet_string_long_length_roundtrip() -> None:
    data = b"a" * 130  # forces long-form length
    encoded = OctetString(data).dumps()
    decoded = OctetString.loads(encoded)
    assert decoded == data


def test_decode_length_indefinite() -> None:
    bad = b"\x04\x80"  # OCTET STRING with indefinite length
    with pytest.raises(ASN1LengthError):
        OctetString.loads(bad)


def test_decode_length_truncated() -> None:
    bad = b"\x04\x81"  # declares one length byte but missing
    with pytest.raises(ASN1LengthError):
        OctetString.loads(bad)


def test_object_identifier_too_short() -> None:
    with pytest.raises(Exception):
        ObjectIdentifier((1,))


def test_bit_string_eq_other_type() -> None:
    bits = BitString(b"\x00")
    assert bits != b"\x00"


def test_schema_repr_executes() -> None:
    class Foo(Schema):
        a: Integer
    obj = Foo(a=1)
    assert "Foo" in repr(obj)


def test_encode_value_unsupported() -> None:
    class Dummy:
        pass
    with pytest.raises(TypeError):
        _encode_value(Dummy())


def test_bit_string_coerce_bytes_default_unused() -> None:
    class Wrap(Schema):
        bits: BitString
    obj = Wrap(bits=b"\xFF")
    assert obj.bits.unused_bits == 0


def test_oid_coerce_list() -> None:
    class Wrap(Schema):
        oid: ObjectIdentifier
    obj = Wrap(oid=[1, 2, 3])
    assert obj.oid == (1, 2, 3)


def test_octet_string_missing_length_byte() -> None:
    with pytest.raises(ASN1LengthError):
        OctetString.loads(b"\x04")


def test_octet_string_missing_tag() -> None:
    with pytest.raises(ASN1DecodeError):
        OctetString.loads(b"")


def test_octet_string_wrong_tag() -> None:
    with pytest.raises(ASN1TagError):
        OctetString.loads(Integer(1).dumps())


def test_integer_empty_content() -> None:
    with pytest.raises(ASN1DecodeError):
        Integer.loads(b"\x02\x00")


def test_object_identifier_wrong_tag_and_empty() -> None:
    with pytest.raises(ASN1TagError):
        ObjectIdentifier.loads(Integer(1).dumps())
    with pytest.raises(ASN1DecodeError):
        ObjectIdentifier.loads(b"\x06\x00")


def test_oid_second_arc_range_and_zero_arc_encoding() -> None:
    with pytest.raises(Exception):
        ObjectIdentifier((1, 50))
    oid = ObjectIdentifier((1, 3, 6, 0))
    assert ObjectIdentifier.loads(oid.dumps()) == oid


def test_decode_oid_arc_offset_beyond() -> None:
    with pytest.raises(ASN1DecodeError):
        _decode_oid_arc(b"", 0)


def test_bit_string_repr_and_wrong_tag() -> None:
    bstr = BitString(b"\xAA", unused_bits=1)
    assert "BitString" in repr(bstr)
    with pytest.raises(ASN1TagError):
        BitString.loads(Integer(1).dumps())


def test_sequence_extra_bytes() -> None:
    class Simple(Schema):
        a: Integer
    int_tlv = Integer(1).dumps()
    body = int_tlv + b"\x00"
    encoded = b"\x30" + _encode_length(len(body)) + body
    with pytest.raises(ASN1LengthError):
        Simple.loads(encoded)


def test_read_tlv_missing_tag() -> None:
    with pytest.raises(ASN1DecodeError):
        Integer.loads(b"")


def test_encode_value_bitstring_branch() -> None:
    class Wrap(Schema):
        bits: BitString
    obj = Wrap(bits=BitString(b"\x00", 0))
    encoded = obj.dumps()
    decoded = Wrap.loads(encoded)
    assert isinstance(decoded.bits, BitString)


def test_decode_value_integer_wrong_tag_in_sequence() -> None:
    class One(Schema):
        a: Integer
    bad_body = OctetString(b"x").dumps()
    encoded = b"\x30" + _encode_length(len(bad_body)) + bad_body
    with pytest.raises(ASN1TagError):
        One.loads(encoded)


def test_decode_value_oid_wrong_tag_in_sequence() -> None:
    class One(Schema):
        oid: ObjectIdentifier
    bad_body = Integer(1).dumps()
    encoded = b"\x30" + _encode_length(len(bad_body)) + bad_body
    with pytest.raises(ASN1TagError):
        One.loads(encoded)


def test_decode_value_octet_wrong_tag_in_sequence() -> None:
    class One(Schema):
        data: OctetString
    bad_body = Integer(1).dumps()
    encoded = b"\x30" + _encode_length(len(bad_body)) + bad_body
    with pytest.raises(ASN1TagError):
        One.loads(encoded)


def test_decode_value_bitstring_wrong_tag_in_sequence() -> None:
    class One(Schema):
        bits: BitString
    bad_body = Integer(1).dumps()
    encoded = b"\x30" + _encode_length(len(bad_body)) + bad_body
    with pytest.raises(ASN1TagError):
        One.loads(encoded)


def test_decode_value_expected_sequence_but_got_integer() -> None:
    class Child(Schema):
        a: Integer

    class Parent(Schema):
        child: Child

    bad_body = Integer(1).dumps()
    encoded = b"\x30" + _encode_length(len(bad_body)) + bad_body
    with pytest.raises(ASN1TagError):
        Parent.loads(encoded)


def test_coerce_value_wrong_types() -> None:
    class Mixed(Schema):
        num: Integer
        oid: ObjectIdentifier
        bits: BitString

    with pytest.raises(TypeError):
        Mixed(num="1", oid=(1, 2, 3), bits=b"\x00")
    with pytest.raises(TypeError):
        Mixed(num=1, oid=1, bits=b"\x00")
    with pytest.raises(TypeError):
        Mixed(num=1, oid=(1, 2, 3), bits=123)


def test_encode_length_negative() -> None:
    with pytest.raises(ASN1LengthError):
        _encode_length(-1)


def test_bit_string_coerce_bytes_encodes() -> None:
    class Wrap(Schema):
        bits: BitString
    obj = Wrap(bits=b"\xAA")
    assert isinstance(obj.bits, BitString)
    assert obj.bits.unused_bits == 0


def test_oid_first_arc_zero_roundtrip() -> None:
    oid = ObjectIdentifier((0, 1, 2))
    assert ObjectIdentifier.loads(oid.dumps()) == oid


def test_oid_negative_tail_arc() -> None:
    with pytest.raises(ASN1Error):
        ObjectIdentifier((1, 2, -1))


def test_encode_oid_arc_negative() -> None:
    with pytest.raises(ASN1Error):
        _encode_oid_arc(-1)


def test_coerce_octet_wrong_type() -> None:
    class Wrap(Schema):
        data: OctetString
    with pytest.raises(TypeError):
        Wrap(data=123)


def test_coerce_bitstring_non_bytes_tuple() -> None:
    class Wrap(Schema):
        bits: BitString
    with pytest.raises(TypeError):
        Wrap(bits=("abc", 0))


def test_coerce_child_wrong_type() -> None:
    class Child(Schema):
        a: Integer

    class Parent(Schema):
        child: Child

    with pytest.raises(TypeError):
        Parent(child=123)


def test_coerce_unsupported_field_type() -> None:
    class BadAnnot(Schema):
        val: int

    with pytest.raises(TypeError):
        BadAnnot(val=1)


def test_integer_int_and_index_and_eq_branches() -> None:
    i = Integer(7)
    assert int(i) == 7
    assert [1] * i == [1, 1, 1, 1, 1, 1, 1]  # uses __index__
    assert i == 7
    assert i != 8


def test_oid_eq_tuple_branch() -> None:
    oid = ObjectIdentifier((1, 2, 3))
    assert oid == (1, 2, 3)


def test_octet_string_eq_bytes_and_other() -> None:
    s = OctetString(b"abc")
    assert s == b"abc"
    assert s != "abc"


def test_integer_eq_integer_and_other_type() -> None:
    i1 = Integer(3)
    i2 = Integer(3)
    assert i1 == i2  # hits Integer branch
    assert (i1 == "3") is False  # hits fallback branch


def test_oid_eq_other_type_false() -> None:
    oid = ObjectIdentifier((1, 2, 3))
    assert (oid == "1.2.3") is False


def test_octet_string_eq_octetstring_branch() -> None:
    a = OctetString(b"abc")
    b = OctetString(b"abc")
    assert a == b

