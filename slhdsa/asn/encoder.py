from slhdsa.asn.nodes import *

        
class RecursiveEncoder:
    @classmethod
    def dump(cls, root: Node) -> bytes:
        if isinstance(root, Integer):
            return root.typ.to_bytes() + root.length.to_bytes() + root.value.to_bytes(root.length)
        if isinstance(root, OctetString):
            return root.typ.to_bytes() + len(root.value).to_bytes() + root.value
        if isinstance(root, Sequence):
            result = b''
            for i in root.children:
                result += cls.dump(i)
            result = root.typ.to_bytes() + len(result).to_bytes() + result
            return result
        result = (root.value[0] * 40 + root.value[1]).to_bytes()
        for i in root.value[2:]:
             if i < 128:
                 result += i.to_bytes()
             else:
                 tmp = bytearray()
                 while i > 0:
                     tmp.append(i&0x7F)
                     i>>=7
                 tmp.reverse()
                 for i in range(len(tmp) - 1):
                     tmp[i] |= 0x80
                 result += bytes(tmp)
        return root.typ.to_bytes() + len(result).to_bytes() + result
