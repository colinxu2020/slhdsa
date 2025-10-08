from slhdsa.asn.nodes import *


class RecursiveParser:
    @classmethod
    def parse(cls, bin: bytes) -> Node:
        return cls._parse(bin)[0]

    @classmethod
    def _parse(cls, bin: bytes) -> tuple[Node, int]:
        if bin[0] == 0x02:
            return Integer(int.from_bytes(bin[2:2+bin[1]]), bin[1]), 2+bin[1]
        if bin[0] == 0x06:
            payload = bin[2:2+bin[1]]
            data = [payload[0]//40, payload[0]%40]
            offset = 1
            while offset < len(payload):
                if (payload[offset] & 128) == 0:
                    data.append(payload[offset])
                    offset += 1
                    continue
                current = 0
                while payload[offset] & 128:
                    current = (current << 7) | (payload[offset] & 0x7F)
                    offset += 1
                current = (current << 7) | (payload[offset] & 0x7F)
                data.append(current)
                offset += 1
            return ObjectId(tuple(data)), 2+bin[1]
        if bin[0] == 0x04:
            return OctetString(bin[2:2+bin[1]]), 2+bin[1]
        if bin[0] == 0x30:
            offset = 2
            result = Sequence([])
            while offset < 2 + bin[1]:
                tmp = cls._parse(bin[offset:])
                result.children.append(tmp[0])
                offset += tmp[1]
            return result, 2 + bin[1]
        raise ValueError("Unknown ASN.1 Type")
        