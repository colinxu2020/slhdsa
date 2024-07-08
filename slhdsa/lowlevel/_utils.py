def trunc(msg: bytes, length: int) -> bytes:
    return msg[:length]


def compact_address(data: bytes) -> bytes:
    return data[3:4] + data[8:16] + data[19:32]


def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


def base2b(data: bytes, b: int, out_len: int) -> list[int]:
    in_ = bits = total = 0
    result = []

    for out in range(out_len):
        while bits < b:
            total = (total << 8) + data[in_]
            in_ += 1
            bits += 8
        bits -= b
        result.append((total >> bits) % (2 ** b))
    return result
