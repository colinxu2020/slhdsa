from typing import ClassVar
from abc import ABC
from dataclasses import dataclass


@dataclass
class Node(ABC):
    typ: ClassVar[int]
    
@dataclass
class Integer(Node):
    typ: ClassVar[int] = 0x02
    value: int
    length: int
    
@dataclass
class ObjectId(Node):
    typ: ClassVar[int] = 0x06
    value: tuple[int]

@dataclass
class OctetString(Node):
    typ: ClassVar[int] = 0x04
    value: bytes

@dataclass
class Sequence(Node):
    typ: ClassVar[int] = 0x30
    children: list[Node]
    