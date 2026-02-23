from __future__ import annotations

from typing import Any, ClassVar, Dict, Iterable, Tuple, Type, TypeVar, get_type_hints

__all__ = [
    "ASN1Error",
    "ASN1DecodeError",
    "ASN1LengthError",
    "ASN1TagError",
    "Integer",
    "ObjectIdentifier",
    "OctetString",
    "BitString",
    "Schema",
    "Sequence",
]


class ASN1Error(ValueError):
    """Base class for ASN.1 encoding/decoding errors."""


class ASN1DecodeError(ASN1Error):
    pass


class ASN1LengthError(ASN1DecodeError):
    pass


class ASN1TagError(ASN1DecodeError):
    pass


_T = TypeVar("_T", bound="Schema")


_TAG_INTEGER = 0x02
_TAG_BIT_STRING = 0x03
_TAG_OCTET_STRING = 0x04
_TAG_OBJECT_ID = 0x06
_TAG_SEQUENCE = 0x30


# Length helpers

def _encode_length(length: int) -> bytes:
    if length < 0:
        raise ASN1LengthError("Length cannot be negative")
    if length < 0x80:
        return bytes([length])
    needed = (length.bit_length() + 7) // 8
    length_bytes = length.to_bytes(needed, "big")
    return bytes([0x80 | needed]) + length_bytes


def _decode_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ASN1LengthError("Missing length byte")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    if count == 0:
        raise ASN1LengthError("Indefinite length not supported")
    if offset + 1 + count > len(data):
        raise ASN1LengthError("Length bytes truncated")
    if count > 1 and data[offset + 1] == 0:
        raise ASN1LengthError("Non-minimal length encoding")
    value = int.from_bytes(data[offset + 1 : offset + 1 + count], "big")
    if value < 0x80:
        raise ASN1LengthError("Non-minimal length encoding")
    return value, offset + 1 + count


# Integer helpers


def _int_to_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    bits = value.bit_length()
    length = max(1, (bits + 7) // 8)
    if value < 0:
        while value < -(1 << (length * 8 - 1)):
            length += 1
    else:
        if value >> (length * 8 - 1):
            length += 1
    return value.to_bytes(length, "big", signed=True)


def _encode_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(content)) + content


class Integer(int):
    def dumps(self) -> bytes:
        return _encode_tlv(_TAG_INTEGER, _int_to_bytes(int(self)))

    @classmethod
    def loads(cls: Type["Integer"], data: bytes) -> "Integer":
        tag, length, start = _read_tlv_header(data, 0)
        if tag != _TAG_INTEGER:
            raise ASN1TagError("Not an INTEGER tag")
        end = start + length
        _ensure_boundary(data, end)
        content = data[start:end]
        _validate_integer_bytes(content)
        return cls(int.from_bytes(content, "big", signed=True))


def _validate_integer_bytes(content: bytes) -> None:
    if not content:
        raise ASN1DecodeError("Empty INTEGER content")
    if len(content) > 1:
        if content[0] == 0x00 and content[1] & 0x80 == 0:
            raise ASN1DecodeError("INTEGER has non-minimal leading 0")
        if content[0] == 0xFF and content[1] & 0x80 == 0x80:
            raise ASN1DecodeError("INTEGER has non-minimal leading 0xFF")


class ObjectIdentifier(tuple):
    def __new__(cls, value: Iterable[int]):
        items = tuple(int(v) for v in value)
        _validate_oid(items)
        return super().__new__(cls, items)

    def dumps(self) -> bytes:
        first, second = self[0], self[1]
        head = bytes([40 * first + second])
        tail = b"".join(_encode_oid_arc(arc) for arc in self[2:])
        return _encode_tlv(_TAG_OBJECT_ID, head + tail)

    @classmethod
    def loads(cls: Type["ObjectIdentifier"], data: bytes) -> "ObjectIdentifier":
        tag, length, start = _read_tlv_header(data, 0)
        if tag != _TAG_OBJECT_ID:
            raise ASN1TagError("Not an OBJECT IDENTIFIER tag")
        end = start + length
        _ensure_boundary(data, end)
        content = data[start:end]
        if not content:
            raise ASN1DecodeError("OBJECT IDENTIFIER is empty")
        first_octet = content[0]
        if first_octet < 40:
            first, second = 0, first_octet
        elif first_octet < 80:
            first, second = 1, first_octet - 40
        else:
            first, second = 2, first_octet - 80
        arcs = [first, second]
        idx = 1
        while idx < len(content):
            arc, idx = _decode_oid_arc(content, idx)
            arcs.append(arc)
        return cls(tuple(arcs))


def _validate_oid(arcs: Tuple[int, ...]) -> None:
    if len(arcs) < 2:
        raise ASN1Error("OID must contain at least two arcs")
    if arcs[0] < 0 or arcs[0] > 2:
        raise ASN1Error("First OID arc must be 0, 1, or 2")
    if arcs[0] < 2 and not (0 <= arcs[1] < 40):
        raise ASN1Error("Second OID arc out of range for first arc 0 or 1")
    for arc in arcs:
        if arc < 0:
            raise ASN1Error("OID arcs must be non-negative")


def _encode_oid_arc(arc: int) -> bytes:
    if arc < 0:
        raise ASN1Error("OID arcs must be non-negative")
    if arc == 0:
        return b"\x00"
    out = bytearray()
    value = arc
    while value > 0:
        out.append(0x80 | (value & 0x7F))
        value >>= 7
    out[0] &= 0x7F
    out.reverse()
    return bytes(out)


def _decode_oid_arc(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ASN1DecodeError("Truncated OID arc")
    value = 0
    while True:
        if offset >= len(data):
            raise ASN1DecodeError("Truncated OID arc")
        b = data[offset]
        value = (value << 7) | (b & 0x7F)
        offset += 1
        if b & 0x80 == 0:
            return value, offset
        # loop continues if continuation bit set


class OctetString(bytes):
    def __new__(cls, value: bytes | bytearray | memoryview):
        return super().__new__(cls, bytes(value))

    def dumps(self) -> bytes:
        return _encode_tlv(_TAG_OCTET_STRING, bytes(self))

    @classmethod
    def loads(cls: Type["OctetString"], data: bytes) -> "OctetString":
        tag, length, start = _read_tlv_header(data, 0)
        if tag != _TAG_OCTET_STRING:
            raise ASN1TagError("Not an OCTET STRING tag")
        end = start + length
        _ensure_boundary(data, end)
        return cls(data[start:end])


class BitString:
    __slots__ = ("data", "unused_bits")

    data: bytes
    unused_bits: int

    def __init__(self, data: bytes | bytearray | memoryview, unused_bits: int = 0):
        if unused_bits < 0 or unused_bits > 7:
            raise ASN1Error("unused_bits must be in range 0..7")
        self.data = bytes(data)
        self.unused_bits = unused_bits

    def __bytes__(self) -> bytes:  # pragma: no cover - trivial
        return self.data

    def __eq__(self, other: object) -> bool:
        if isinstance(other, BitString):
            return self.data == other.data and self.unused_bits == other.unused_bits
        return False

    def __repr__(self) -> str:
        return f"BitString(data={self.data!r}, unused_bits={self.unused_bits})"

    def dumps(self) -> bytes:
        content = bytes([self.unused_bits]) + self.data
        return _encode_tlv(_TAG_BIT_STRING, content)

    @classmethod
    def loads(cls: Type["BitString"], data: bytes) -> "BitString":
        tag, length, start = _read_tlv_header(data, 0)
        if tag != _TAG_BIT_STRING:
            raise ASN1TagError("Not a BIT STRING tag")
        end = start + length
        _ensure_boundary(data, end)
        if length == 0:
            raise ASN1DecodeError("BIT STRING missing unused bits byte")
        unused = data[start]
        payload = data[start + 1 : end]
        return cls(payload, unused)


class Schema:
    _fields_cache: ClassVar[Dict[Type["Schema"], tuple[str, ...]]] = {}
    _types_cache: ClassVar[Dict[Type["Schema"], Dict[str, Type[Any]]]] = {}

    def __init__(self, **kwargs: Any) -> None:
        fields = self._field_names()
        types = self._field_types()
        missing = [name for name in fields if name not in kwargs]
        if missing:
            raise TypeError(f"Missing fields for {self.__class__.__name__}: {', '.join(missing)}")
        extra = [name for name in kwargs if name not in fields]
        if extra:
            raise TypeError(f"Unexpected fields for {self.__class__.__name__}: {', '.join(extra)}")
        for name in fields:
            expected = types[name]
            value = _coerce_value(expected, kwargs[name])
            setattr(self, name, value)

    @classmethod
    def _field_names(cls) -> tuple[str, ...]:
        cached = Schema._fields_cache.get(cls)
        if cached is not None:
            return cached
        annotations = getattr(cls, "__annotations__", {})
        names = tuple(annotations.keys())
        Schema._fields_cache[cls] = names
        return names

    @classmethod
    def _field_types(cls) -> Dict[str, Type[Any]]:
        cached = Schema._types_cache.get(cls)
        if cached is not None:
            return cached
        hints = get_type_hints(cls, globalns=_module_globals(cls))
        Schema._types_cache[cls] = hints
        return hints

    def dumps(self) -> bytes:
        body = b"".join(_encode_value(getattr(self, name)) for name in self._field_names())
        return _encode_tlv(_TAG_SEQUENCE, body)

    @classmethod
    def loads(cls: Type[_T], data: bytes) -> _T:
        tag, length, start = _read_tlv_header(data, 0)
        if tag != _TAG_SEQUENCE:
            raise ASN1TagError(f"Expected SEQUENCE for {cls.__name__}")
        end = start + length
        _ensure_boundary(data, end)
        offset = start
        types = cls._field_types()
        values: Dict[str, Any] = {}
        for name in cls._field_names():
            expected = types[name]
            value, offset = _decode_value(data, offset, expected)
            values[name] = value
        if offset != end:
            raise ASN1LengthError("Extra bytes found after decoding SEQUENCE")
        return cls(**values)

    def __bytes__(self) -> bytes:  # pragma: no cover - trivial
        return self.dumps()

    def __repr__(self) -> str:
        parts = ", ".join(f"{name}={getattr(self, name)!r}" for name in self._field_names())
        return f"{self.__class__.__name__}({parts})"


class Sequence(Schema):
    """Semantic alias for ASN.1 SEQUENCE."""


def _module_globals(cls: Type[Any]) -> Dict[str, Any]:
    import sys
    import typing

    env = dict(sys.modules[cls.__module__].__dict__)
    for name, value in typing.__dict__.items():
        if name not in env:
            env[name] = value
    env.setdefault("Schema", Schema)
    env.setdefault("Sequence", Sequence)
    env.setdefault("Integer", Integer)
    env.setdefault("ObjectIdentifier", ObjectIdentifier)
    env.setdefault("OctetString", OctetString)
    env.setdefault("BitString", BitString)
    return env


def _read_tlv_header(data: bytes, offset: int) -> tuple[int, int, int]:
    if offset >= len(data):
        raise ASN1DecodeError("Missing tag")
    tag = data[offset]
    length, next_offset = _decode_length(data, offset + 1)
    return tag, length, next_offset


def _ensure_boundary(data: bytes, end: int) -> None:
    if end > len(data):
        raise ASN1LengthError("Content length exceeds available data")


def _encode_value(value: Any) -> bytes:
    if isinstance(value, Integer):
        return value.dumps()
    if isinstance(value, ObjectIdentifier):
        return value.dumps()
    if isinstance(value, OctetString):
        return value.dumps()
    if isinstance(value, BitString):
        return value.dumps()
    if isinstance(value, Schema):
        return value.dumps()
    raise TypeError(f"Unsupported ASN.1 value type: {type(value)!r}")


def _decode_value(data: bytes, offset: int, expected: Type[Any]) -> tuple[Any, int]:
    if expected is Integer or issubclass(expected, Integer):
        tag, length, start = _read_tlv_header(data, offset)
        if tag != _TAG_INTEGER:
            raise ASN1TagError("Expected INTEGER")
        end = start + length
        _ensure_boundary(data, end)
        value = Integer.loads(data[offset:end])
        return value, end
    if expected is ObjectIdentifier or issubclass(expected, ObjectIdentifier):
        tag, length, start = _read_tlv_header(data, offset)
        if tag != _TAG_OBJECT_ID:
            raise ASN1TagError("Expected OBJECT IDENTIFIER")
        end = start + length
        _ensure_boundary(data, end)
        value = ObjectIdentifier.loads(data[offset:end])
        return value, end
    if expected is OctetString or issubclass(expected, OctetString):
        tag, length, start = _read_tlv_header(data, offset)
        if tag != _TAG_OCTET_STRING:
            raise ASN1TagError("Expected OCTET STRING")
        end = start + length
        _ensure_boundary(data, end)
        value = OctetString.loads(data[offset:end])
        return value, end
    if expected is BitString or issubclass(expected, BitString):
        tag, length, start = _read_tlv_header(data, offset)
        if tag != _TAG_BIT_STRING:
            raise ASN1TagError("Expected BIT STRING")
        end = start + length
        _ensure_boundary(data, end)
        value = BitString.loads(data[offset:end])
        return value, end
    if issubclass(expected, Schema):
        tag, length, start = _read_tlv_header(data, offset)
        if tag != _TAG_SEQUENCE:
            raise ASN1TagError(f"Expected SEQUENCE for {expected.__name__}")
        end = start + length
        _ensure_boundary(data, end)
        value = expected.loads(data[offset:end])
        return value, end
    raise TypeError(f"Unsupported field type: {expected!r}")


def _coerce_value(expected: Type[Any], value: Any) -> Any:
    if expected is Integer or issubclass(expected, Integer):
        if isinstance(value, Integer):
            return value
        if isinstance(value, int):
            return Integer(value)
        raise TypeError("Expected int for INTEGER field")
    if expected is ObjectIdentifier or issubclass(expected, ObjectIdentifier):
        if isinstance(value, ObjectIdentifier):
            return value
        if isinstance(value, tuple) or isinstance(value, list):
            return ObjectIdentifier(tuple(int(v) for v in value))
        raise TypeError("Expected tuple for OBJECT IDENTIFIER field")
    if expected is OctetString or issubclass(expected, OctetString):
        if isinstance(value, OctetString):
            return value
        if isinstance(value, (bytes, bytearray, memoryview)):
            return OctetString(bytes(value))
        raise TypeError("Expected bytes for OCTET STRING field")
    if expected is BitString or issubclass(expected, BitString):
        if isinstance(value, BitString):
            return value
        if isinstance(value, tuple) and len(value) == 2:
            data, unused = value
            if not isinstance(data, (bytes, bytearray, memoryview)):
                raise TypeError("BitString data must be bytes-like")
            return BitString(bytes(data), int(unused))
        if isinstance(value, (bytes, bytearray, memoryview)):
            return BitString(bytes(value), 0)
        raise TypeError("Expected BitString or (data, unused_bits)")
    if issubclass(expected, Schema):
        if isinstance(value, expected):
            return value
        if isinstance(value, dict):
            return expected(**value)
        raise TypeError(f"Expected {expected.__name__} for SEQUENCE field")
    raise TypeError(f"Unsupported field type: {expected!r}")
