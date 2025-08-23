from typing import TypeVar, ClassVar

T = TypeVar("T", bound="Address")


class Address:
    layer: int
    tree: int
    typ: ClassVar[int] = 0

    def __init__(self, layer: int, tree: int) -> None:
        self.layer = layer
        self.tree = tree

    def to_bytes(self) -> bytes:
        return self.layer.to_bytes(4, "big") + self.tree.to_bytes(12, "big") + self.typ.to_bytes(4, "big")

    def with_type(self, typ: type[T]) -> T:
        return typ(self.layer, self.tree)

class WOTSHashAddress(Address):
    typ: ClassVar[int] = 0
    keypair: int = 0
    chain: int = 0
    hash: int = 0

    def to_bytes(self) -> bytes:
        return super().to_bytes() + self.keypair.to_bytes(4, "big") + self.chain.to_bytes(4, "big") + self.hash.to_bytes(4, "big")

class WOTSPKAddress(Address):
    typ: ClassVar[int] = 1
    keypair: int = 0

    def to_bytes(self) -> bytes:
        return super().to_bytes() + self.keypair.to_bytes(4, "big") + b'\x00' * 8

class TreeAddress(Address):
    typ: ClassVar[int] = 2
    height: int = 0
    index: int = 0

    def to_bytes(self) -> bytes:
        return super().to_bytes() + b'\x00' * 4 + self.height.to_bytes(4, "big") + self.index.to_bytes(4, "big")

class FORSTreeAddress(Address):
    typ: ClassVar[int] = 3
    keypair: int = 0
    height: int = 0
    index: int = 0

    def to_bytes(self) -> bytes:
        return super().to_bytes() + self.keypair.to_bytes(4, "big") + self.height.to_bytes(4, "big") + self.index.to_bytes(4, "big")

class FORSRootsAddress(Address):
    typ: ClassVar[int] = 4
    keypair: int = 0

    def to_bytes(self) -> bytes:
        return super().to_bytes() + self.keypair.to_bytes(4, "big") + b'\x00' * 8

class WOTSPrfAddress(Address):
    typ: ClassVar[int] = 5
    keypair: int = 0
    chain: int = 0
    hash: int = 0

    def to_bytes(self) -> bytes:
        return super().to_bytes() + self.keypair.to_bytes(4, "big") + self.chain.to_bytes(4, "big") + self.hash.to_bytes(4, "big")

class FORSPrfAddress(Address):
    typ: ClassVar[int] = 6
    keypair: int = 0
    height: int = 0
    index: int = 0

    def to_bytes(self) -> bytes:
        return super().to_bytes() + self.keypair.to_bytes(4, "big") + self.height.to_bytes(4, "big") + self.index.to_bytes(4, "big")
