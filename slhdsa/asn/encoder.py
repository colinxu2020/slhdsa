from slhdsa.asn.nodes import *

        
class RecursiveEncoder:
    @classmethod
    def dump(cls, root: Node) -> bytes:
        if isinstance(root, Integer):
            return root.typ.to_bytes(1, "big") + root.length.to_bytes(1, "big") + root.value.to_bytes(root.length, "big")
        if isinstance(root, OctetString):
            return root.typ.to_bytes(1, "big") + len(root.value).to_bytes(1, "big") + root.value
        if isinstance(root, Sequence):
            result = b''
            for i in root.children:
                result += cls.dump(i)
            result = root.typ.to_bytes(1, "big") + len(result).to_bytes(1, "big") + result
            return result
        if isinstance(root, ObjectId):
            result = (root.value[0] * 40 + root.value[1]).to_bytes(1, "big")
            for i in root.value[2:]:
                 if i < 128:
                     result += i.to_bytes(1, "big")
                 else:
                     tmp = bytearray()
                     while i > 0:
                         tmp.append(i&0x7F)
                         i>>=7
                     tmp.reverse()
                     for j in range(len(tmp) - 1):
                         tmp[j] = int(tmp[j]) | 0x80
                     result += bytes(tmp)
            return root.typ.to_bytes(1, "big") + len(result).to_bytes(1, "big") + result
        raise TypeError("Unknown Type")