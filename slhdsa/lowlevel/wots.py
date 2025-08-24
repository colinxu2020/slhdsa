from dataclasses import dataclass
from math import log2

from slhdsa.lowlevel.parameters import Parameter
from slhdsa.lowlevel._utils import ceil_div, base2b
from slhdsa.lowlevel.addresses import WOTSHashAddress, WOTSPKAddress, WOTSPrfAddress


@dataclass
class WOTSParameter:
    w: int
    len1: int
    len2: int
    len: int

    def __init__(self, par: Parameter) -> None:
        self.w = 2 ** par.lgw
        self.len1 = ceil_div(8 * par.n, par.lgw)
        self.len2 = int(log2(self.len1 * (self.w - 1))) // par.lgw + 1
        self.len = self.len1 + self.len2


@dataclass
class WOTS:
    wots_parameter: WOTSParameter
    parameter: Parameter

    def _chain(self, key: bytes, beg: int, step: int, pk_seed: bytes, address: WOTSHashAddress) -> bytes:
        #if beg + step >= self.wots_parameter.w:
        #    return b""
        tmp = key
        for j in range(beg, beg + step):
            address.hash = j
            tmp = self.parameter.F(pk_seed, address, tmp)
        return tmp

    def generate_publickey(self, sk_seed: bytes, pk_seed: bytes, address: WOTSHashAddress) -> bytes:
        sk_address = address.with_type(WOTSPrfAddress)
        sk_address.keypair = address.keypair
        tmp = b""
        for i in range(self.wots_parameter.len):
            sk_address.chain = i
            sk = self.parameter.PRF(pk_seed, sk_seed, sk_address)
            address.chain = i
            tmp += self._chain(sk, 0, self.wots_parameter.w - 1, pk_seed, address)
        wots_pk_address = address.with_type(WOTSPKAddress)
        wots_pk_address.keypair = address.keypair
        return self.parameter.Tl(pk_seed, wots_pk_address, tmp)

    def _format_message(self, msg_: bytes) -> list[int]:
        msg = base2b(msg_, self.parameter.lgw, self.wots_parameter.len1)
        csum = 0
        for i in range(self.wots_parameter.len1):
            csum = csum + self.wots_parameter.w - 1 - msg[i]
        csum = csum << ((8 | -((self.wots_parameter.len2 * self.parameter.lgw) % 8)) % 8)
        msg = msg + base2b(csum.to_bytes(ceil_div(self.wots_parameter.len2 * self.parameter.lgw, 8), "big"),
                           self.parameter.lgw, self.wots_parameter.len2)
        return msg

    def sign(self, msg_: bytes, sk_seed: bytes, pk_seed: bytes, address: WOTSHashAddress) -> bytes:
        msg = self._format_message(msg_)
        sk_address = address.with_type(WOTSPrfAddress)
        sk_address.keypair = address.keypair
        sig = b''
        for i in range(self.wots_parameter.len):
            sk_address.chain = i
            sk = self.parameter.PRF(pk_seed, sk_seed, sk_address)
            address.chain = i
            sig += self._chain(sk, 0, msg[i], pk_seed, address)
        return sig

    def publickey_from_sign(self, sig: bytes, msg_: bytes, pk_seed: bytes, address: WOTSHashAddress) -> bytes:
        msg = self._format_message(msg_)
        tmp = b''
        for i in range(self.wots_parameter.len):
            address.chain = i
            tmp += self._chain(sig[i * self.parameter.n:(i + 1) * self.parameter.n], msg[i],
                               self.wots_parameter.w - 1 - msg[i], pk_seed, address)
        wots_pk_address = address.with_type(WOTSPKAddress)
        wots_pk_address.keypair = address.keypair
        pk = self.parameter.Tl(pk_seed, wots_pk_address, tmp)
        return pk
