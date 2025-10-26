from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any, ClassVar, TypeVar, get_args, get_origin, get_type_hints

__all__ = ["Schema", "Sequence", "Integer", "OctetString", "ObjectIdentifier"]


class _SequenceMeta(type):
    def __getitem__(cls, parameters: Any) -> Any:
        if not isinstance(parameters, tuple):
            parameters = (parameters,)
        return Annotated[cls, parameters]


class Sequence(metaclass=_SequenceMeta):
    """Marker used inside typing.Annotated metadata to describe ASN.1 SEQUENCE nodes."""


class OctetString(bytes):
    """Runtime representation of ASN.1 OCTET STRING that behaves like bytes."""

    _asn_descriptor: ClassVar["_OctetStringDescriptor"]

    def __new__(cls, value: bytes | bytearray | memoryview) -> "OctetString":
        return bytes.__new__(cls, bytes(value))


class _ASN1Type:
    tag: int

    def decode(self, data: bytes, offset: int) -> tuple[Any, int]:
        raise NotImplementedError

    def encode(self, value: Any) -> bytes:
        raise NotImplementedError


@dataclass(frozen=True)
class _FieldSpec:
    name: str
    descriptor: _ASN1Type


def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("ASN.1 length is truncated")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0:
        raise ValueError("Indefinite lengths are not supported")
    if offset + count > len(data):
        raise ValueError("ASN.1 length is truncated")
    length = int.from_bytes(data[offset:offset + count], "big")
    return length, offset + count


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("ASN.1 tag is truncated")
    tag = data[offset]
    offset += 1
    length, offset = _read_length(data, offset)
    end = offset + length
    if end > len(data):
        raise ValueError("ASN.1 payload is truncated")
    return tag, data[offset:end], end


def _encode_length(length: int) -> bytes:
    if length < 0:
        raise ValueError("Negative length is not allowed")
    if length < 0x80:
        return bytes((length,))
    needed = (length.bit_length() + 7) // 8
    return bytes((0x80 | needed,)) + length.to_bytes(needed, "big")


def _encode_tlv(tag: int, payload: bytes) -> bytes:
    return bytes((tag,)) + _encode_length(len(payload)) + payload


def _encode_integer_content(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    signed = value < 0
    size = max(1, (value.bit_length() + 7) // 8)
    content = value.to_bytes(size, "big", signed=True)
    while len(content) > 1:
        if not signed and content[0] == 0x00 and (content[1] & 0x80) == 0:
            content = content[1:]
            continue
        if signed and content[0] == 0xFF and (content[1] & 0x80) == 0x80:
            content = content[1:]
            continue
        break
    if not signed and (content[0] & 0x80):
        content = b"\x00" + content
    return content


def _encode_base128(value: int) -> bytes:
    if value < 0:
        raise ValueError("Object identifier components must be non-negative")
    if value == 0:
        return b"\x00"
    encoded = bytearray()
    while value:
        encoded.append(value & 0x7F)
        value >>= 7
    encoded.reverse()
    for idx in range(len(encoded) - 1):
        encoded[idx] |= 0x80
    return bytes(encoded)


class _IntegerDescriptor(_ASN1Type):
    tag = 0x02
    python_type = int

    def decode(self, data: bytes, offset: int) -> tuple[int, int]:
        tag, payload, end = _read_tlv(data, offset)
        if tag != self.tag:
            raise ValueError("Unexpected tag for INTEGER")
        return int.from_bytes(payload, "big", signed=True), end

    def encode(self, value: Any) -> bytes:
        if not isinstance(value, int):
            raise TypeError("INTEGER expects an int value")
        return _encode_tlv(self.tag, _encode_integer_content(value))


class _OctetStringDescriptor(_ASN1Type):
    tag = 0x04
    python_type = OctetString

    def decode(self, data: bytes, offset: int) -> tuple[OctetString, int]:
        tag, payload, end = _read_tlv(data, offset)
        if tag != self.tag:
            raise ValueError("Unexpected tag for OCTET STRING")
        return OctetString(payload), end

    def encode(self, value: Any) -> bytes:
        if isinstance(value, OctetString):
            payload = bytes(value)
        elif isinstance(value, (bytes, bytearray, memoryview)):
            payload = bytes(value)
        else:
            raise TypeError("OCTET STRING expects a bytes-like value")
        return _encode_tlv(self.tag, payload)


class _ObjectIdentifierDescriptor(_ASN1Type):
    tag = 0x06
    python_type = tuple

    def decode(self, data: bytes, offset: int) -> tuple[tuple[int, ...], int]:
        tag, payload, end = _read_tlv(data, offset)
        if tag != self.tag:
            raise ValueError("Unexpected tag for OBJECT IDENTIFIER")
        if not payload:
            raise ValueError("OBJECT IDENTIFIER payload is empty")
        first = payload[0]
        values: list[int] = [first // 40, first % 40]
        current = 0
        idx = 1
        while idx < len(payload):
            byte = payload[idx]
            current = (current << 7) | (byte & 0x7F)
            if byte & 0x80:
                idx += 1
                continue
            values.append(current)
            current = 0
            idx += 1
        if current != 0:
            raise ValueError("OBJECT IDENTIFIER payload is truncated")
        return tuple(values), end

    def encode(self, value: Any) -> bytes:
        if not isinstance(value, tuple):
            raise TypeError("OBJECT IDENTIFIER expects a tuple of integers")
        if len(value) < 2:
            raise ValueError("OBJECT IDENTIFIER must have at least two components")
        first, second = value[0], value[1]
        if first < 0 or first > 2:
            raise ValueError("Invalid OBJECT IDENTIFIER first component")
        if second < 0:
            raise ValueError("Invalid OBJECT IDENTIFIER second component")
        if first < 2 and second >= 40:
            raise ValueError("Invalid OBJECT IDENTIFIER second component for first component < 2")
        payload = bytearray()
        payload.append(first * 40 + second)
        for component in value[2:]:
            if not isinstance(component, int):
                raise TypeError("OBJECT IDENTIFIER components must be integers")
            payload.extend(_encode_base128(component))
        return _encode_tlv(self.tag, bytes(payload))


def _extract_sequence_element_types(annotation: Any) -> tuple[Any, ...]:
    origin = get_origin(annotation)
    if origin not in (tuple, list, set):
        return ()
    args = get_args(annotation)
    if not args:
        return ()
    return args


def _expected_type_for_index(element_types: tuple[Any, ...], index: int) -> Any | None:
    if not element_types:
        return None
    if len(element_types) == 1:
        return element_types[0]
    if len(element_types) == 2 and element_types[1] is Ellipsis:
        return element_types[0]
    if index < len(element_types):
        candidate = element_types[index]
        if candidate is Ellipsis:
            return element_types[index - 1] if index > 0 else None
        return candidate
    if element_types and element_types[-1] is Ellipsis:
        return element_types[-2] if len(element_types) >= 2 else None
    return None


def _strip_annotated(expected: Any) -> Any:
    if get_origin(expected) is Annotated:
        return get_args(expected)[0]
    return expected


def _coerce_value_to_python_type(value: Any, expected: Any | None) -> Any:
    if expected is None:
        return value
    expected = _strip_annotated(expected)
    if expected is Any:
        return value
    if expected == Any:
        return value
    if expected is bytes:
        if isinstance(value, OctetString):
            return bytes(value)
        if isinstance(value, (bytearray, memoryview)):
            return bytes(value)
    return value


class _SequenceDescriptor(_ASN1Type):
    tag = 0x30

    def __init__(
        self,
        children: tuple[_ASN1Type, ...],
        python_type: Any,
        element_types: tuple[Any, ...] = (),
    ):
        self._children = children
        self._python_type = python_type
        self._element_types = element_types

    def decode(self, data: bytes, offset: int) -> tuple[Any, int]:
        tag, payload, end = _read_tlv(data, offset)
        if tag != self.tag:
            raise ValueError("Unexpected tag for SEQUENCE")
        inner_offset = 0
        collected: list[Any] = []
        while inner_offset < len(payload):
            if len(collected) >= len(self._children):
                raise ValueError("SEQUENCE contains more elements than expected")
            descriptor = self._children[len(collected)]
            value, inner_offset = descriptor.decode(payload, inner_offset)
            expected = _expected_type_for_index(self._element_types, len(collected))
            collected.append(_coerce_value_to_python_type(value, expected))
        if len(collected) != len(self._children):
            raise ValueError("SEQUENCE contains fewer elements than expected")
        return self._build_python_value(collected), end

    def encode(self, value: Any) -> bytes:
        items = self._prepare_iterable(value)
        if len(items) != len(self._children):
            raise ValueError("SEQUENCE length does not match schema definition")
        pieces = [descriptor.encode(item) for descriptor, item in zip(self._children, items)]
        return _encode_tlv(self.tag, b"".join(pieces))

    def _build_python_value(self, values: list[Any]) -> Any:
        target = self._python_type
        if target is tuple:
            return tuple(values)
        if target is list:
            return list(values)
        if target is set:
            return set(values)
        if isinstance(target, type) and issubclass(target, Schema):
            obj = target.__new__(target)
            for spec, value in zip(target._asn_fields, values):
                setattr(obj, spec.name, value)
            return obj
        if callable(target):
            return target(values)
        return tuple(values)

    def _prepare_iterable(self, value: Any) -> tuple[Any, ...]:
        if isinstance(value, tuple):
            return value
        if isinstance(value, list):
            return tuple(value)
        if isinstance(value, set):
            return tuple(value)
        if isinstance(value, Schema) and isinstance(self._python_type, type) and issubclass(self._python_type, Schema):
            return tuple(getattr(value, spec.name) for spec in value._asn_fields)
        if hasattr(value, "__iter__"):
            return tuple(value)
        raise TypeError("SEQUENCE value must be an iterable")


class _SchemaFieldDescriptor(_ASN1Type):
    tag = 0x30

    def __init__(self, schema_cls: type["Schema"]):
        self._schema_cls = schema_cls

    def decode(self, data: bytes, offset: int) -> tuple["Schema", int]:
        return self._schema_cls._decode_stream(data, offset)

    def encode(self, value: Any) -> bytes:
        if not isinstance(value, self._schema_cls):
            raise TypeError("Value does not match schema field type")
        return value.dumps()


_INTEGER_DESCRIPTOR = _IntegerDescriptor()
_OCTET_STRING_DESCRIPTOR = _OctetStringDescriptor()
_OBJECT_IDENTIFIER_DESCRIPTOR = _ObjectIdentifierDescriptor()

OctetString._asn_descriptor = _OCTET_STRING_DESCRIPTOR

Integer = Annotated[int, _INTEGER_DESCRIPTOR]
ObjectIdentifier = Annotated[tuple[int, ...], _OBJECT_IDENTIFIER_DESCRIPTOR]


def _normalize_python_type(annotation: Any) -> Any:
    origin = get_origin(annotation)
    if origin is not None:
        return origin
    if isinstance(annotation, type):
        return annotation
    return tuple


def _descriptor_from_annotation(annotation: Any, python_type: Any | None = None) -> _ASN1Type:
    base, extras = _unpack_annotated(annotation)
    normalized_python_type = _normalize_python_type(python_type if python_type is not None else base)
    element_types = _extract_sequence_element_types(base)
    descriptor: _ASN1Type | None = None
    for extra in extras:
        descriptor = _descriptor_from_extra(extra, normalized_python_type, descriptor, element_types)
    if descriptor is None:
        descriptor = _descriptor_from_base(base, normalized_python_type, element_types)
    if descriptor is None:
        if isinstance(base, type) and base is Sequence:
            raise TypeError("Sequence annotations must include element descriptors")
        raise TypeError(f"Unsupported ASN.1 annotation: {annotation!r}")
    return descriptor


def _descriptor_from_extra(
    extra: Any,
    python_type: Any,
    current: _ASN1Type | None,
    element_types: tuple[Any, ...],
) -> _ASN1Type | None:
    resolved = _resolve_descriptor(extra, python_type, element_types)
    return resolved if resolved is not None else current


def _resolve_descriptor(candidate: Any, python_type: Any, element_types: tuple[Any, ...]) -> _ASN1Type | None:
    if isinstance(candidate, _ASN1Type):
        if isinstance(candidate, _SequenceDescriptor):
            return _SequenceDescriptor(candidate._children, python_type, element_types)
        return candidate
    if isinstance(candidate, type):
        if issubclass(candidate, Schema):
            return _SchemaFieldDescriptor(candidate)
        descriptor = getattr(candidate, "_asn_descriptor", None)
        if isinstance(descriptor, _ASN1Type):
            return descriptor
    origin = get_origin(candidate)
    if origin is Annotated:
        base, extras = _unpack_annotated(candidate)
        if isinstance(base, type) and base is Sequence:
            if not extras:
                raise TypeError("Sequence annotations must include element descriptors")
            children = extras[0]
            if not isinstance(children, tuple):
                children = (children,)
            child_descriptors = tuple(_descriptor_from_annotation(child) for child in children)
            return _SequenceDescriptor(
                child_descriptors,
                _normalize_python_type(python_type),
                element_types,
            )
        return _descriptor_from_annotation(candidate, python_type)
    return None


def _descriptor_from_base(base: Any, python_type: Any, element_types: tuple[Any, ...]) -> _ASN1Type | None:
    resolved = _resolve_descriptor(base, python_type, element_types)
    if resolved is not None:
        return resolved
    origin = get_origin(base)
    if origin is not None:
        return _descriptor_from_base(origin, python_type, element_types)
    return None


def _unpack_annotated(annotation: Any) -> tuple[Any, tuple[Any, ...]]:
    if get_origin(annotation) is Annotated:
        args = get_args(annotation)
        return args[0], tuple(args[1:])
    return annotation, ()


class _SchemaMeta(type):
    _asn_fields: ClassVar[tuple[_FieldSpec, ...]]
    _asn_descriptor: ClassVar[_SequenceDescriptor]
    __slots__: ClassVar[tuple[str, ...]]

    def __new__(mcls, name: str, bases: tuple[type, ...], namespace: dict[str, Any]) -> type:
        cls = super().__new__(mcls, name, bases, namespace)
        if name == "Schema":
            base_fields: tuple[_FieldSpec, ...] = ()
            setattr(cls, "_asn_fields", base_fields)
            setattr(cls, "_asn_descriptor", _SequenceDescriptor((), tuple))
            setattr(cls, "__slots__", ())
            return cls
        resolved_hints = get_type_hints(cls, include_extras=True)
        own_annotations = namespace.get("__annotations__", {})
        field_specs: list[_FieldSpec] = []
        seen: set[str] = set()
        for base in cls.__mro__[1:]:
            base_fields = getattr(base, "_asn_fields", ())
            for spec in base_fields:
                if spec.name not in seen:
                    field_specs.append(spec)
                    seen.add(spec.name)
        for name_key in own_annotations:
            if name_key not in resolved_hints:
                raise TypeError(f"Annotation for field {name_key!r} could not be resolved")
            descriptor = _descriptor_from_annotation(resolved_hints[name_key])
            spec = _FieldSpec(name_key, descriptor)
            if name_key in seen:
                for idx, existing in enumerate(field_specs):
                    if existing.name == name_key:
                        field_specs[idx] = spec
                        break
            else:
                field_specs.append(spec)
                seen.add(name_key)
        field_tuple = tuple(field_specs)
        descriptor = _SequenceDescriptor(tuple(spec.descriptor for spec in field_tuple), tuple)
        setattr(cls, "_asn_fields", field_tuple)
        setattr(cls, "_asn_descriptor", descriptor)
        setattr(cls, "__slots__", tuple(spec.name for spec in field_tuple))
        return cls


SchemaT = TypeVar("SchemaT", bound="Schema")


class Schema(metaclass=_SchemaMeta):
    __slots__ = ()
    _asn_fields: ClassVar[tuple[_FieldSpec, ...]]
    _asn_descriptor: ClassVar[_SequenceDescriptor]

    def __init__(self, *values: Any, **named_values: Any) -> None:
        field_count = len(self._asn_fields)
        if values:
            if named_values:
                raise TypeError("Cannot mix positional and keyword arguments when constructing a schema")
            if len(values) != field_count:
                raise TypeError(f"Expected {field_count} values, got {len(values)}")
            for spec, value in zip(self._asn_fields, values):
                setattr(self, spec.name, value)
            return
        if len(named_values) != field_count:
            missing = [spec.name for spec in self._asn_fields if spec.name not in named_values]
            if missing:
                raise TypeError(f"Missing values for fields: {', '.join(missing)}")
            raise TypeError("Unexpected number of values for schema construction")
        for spec in self._asn_fields:
            setattr(self, spec.name, named_values.pop(spec.name))

    def dumps(self) -> bytes:
        values = [getattr(self, spec.name) for spec in self._asn_fields]
        return self._asn_descriptor.encode(values)

    @classmethod
    def loads(cls: type[SchemaT], data: bytes) -> SchemaT:
        obj, offset = cls._decode_stream(data, 0)
        if offset != len(data):
            raise ValueError("Trailing bytes after ASN.1 structure")
        return obj

    @classmethod
    def _decode_stream(cls: type[SchemaT], data: bytes, offset: int) -> tuple[SchemaT, int]:
        items, new_offset = cls._asn_descriptor.decode(data, offset)
        instance = cls.__new__(cls)
        for spec, value in zip(cls._asn_fields, items):
            setattr(instance, spec.name, value)
        return instance, new_offset

    def __repr__(self) -> str:
        parts = ", ".join(f"{spec.name}={getattr(self, spec.name)!r}" for spec in self._asn_fields)
        return f"{self.__class__.__name__}({parts})"
