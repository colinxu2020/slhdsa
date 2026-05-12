from dataclasses import dataclass

from slhdsa.lowlevel.wots import WOTS, WOTSParameter
from slhdsa.lowlevel.addresses import WOTSHashAddress, TreeAddress, Address
from slhdsa.lowlevel.parameters import Parameter


@dataclass
class XMSS:
    wots: WOTS
    parameter: Parameter

    def __init__(self, parameter: Parameter):
        self.wots = WOTS(WOTSParameter(parameter), parameter)
        self.parameter = parameter

    def node(self, sk_seed: bytes, cur: int, dep: int, pk_seed: bytes, address: Address) -> bytes:
        if dep > self.parameter.h_m or cur >= (1 << (self.parameter.h_m - dep)):
            return b""
        if dep == 0:
            address = address.with_type(WOTSHashAddress)
            address.keypair = cur
            val = self.wots.generate_publickey(sk_seed, pk_seed, address)
        else:
            left_node = self.node(sk_seed, 2 * cur, dep - 1, pk_seed, address)
            right_node = self.node(sk_seed, 2 * cur + 1, dep - 1, pk_seed, address)
            address = address.with_type(TreeAddress)
            address.height = dep
            address.index = cur
            val = self.parameter.H(pk_seed, address, left_node + right_node)
        return val

    def sign(self, msg: bytes, sk_seed: bytes, idx: int, pk_seed: bytes, address: Address, out: memoryview) -> None:
        address_wots = address.with_type(WOTSHashAddress)
        address_wots.keypair = idx
        wots_sig_len = self.parameter.n * self.wots.wots_parameter.len
        self.wots.sign(msg, sk_seed, pk_seed, address_wots, out[:wots_sig_len])

        offset = wots_sig_len
        for j in range(self.parameter.h_m):
            k = (idx // (1 << j)) ^ 1
            out[offset:offset+self.parameter.n] = self.node(sk_seed, k, j, pk_seed, address)
            offset += self.parameter.n

    def public_key_from_sign(self, idx: int, sig: memoryview, msg: bytes, pk_seed: bytes, address: Address) -> bytes:
        address_wots = address.with_type(WOTSHashAddress)
        address_wots.keypair = idx
        wots_sig_len = self.parameter.n * self.wots.wots_parameter.len
        auth = sig[wots_sig_len:wots_sig_len + self.parameter.h_m * self.parameter.n]
        wots_sig = sig[:wots_sig_len]
        node = self.wots.publickey_from_sign(wots_sig, msg, pk_seed, address_wots)
        address = address.with_type(TreeAddress)
        address.index = idx

        for k in range(self.parameter.h_m):
            address.height = k + 1
            auth_k = auth[k * self.parameter.n:(k + 1) * self.parameter.n]
            if (idx // (1 << k)) % 2 == 0:
                address.index //= 2
                buf = bytearray()
                buf.extend(node)
                buf.extend(auth_k)
                node = self.parameter.H(pk_seed, address, memoryview(buf))
            else:
                address.index = (address.index - 1) // 2
                buf = bytearray()
                buf.extend(auth_k)
                buf.extend(node)
                node = self.parameter.H(pk_seed, address, memoryview(buf))
        return node
