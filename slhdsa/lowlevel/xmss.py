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
        if dep > self.parameter.h_m or cur >= 2 ** (self.parameter.h_m - dep):
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

    def sign(self, msg: bytes, sk_seed: bytes, idx: int, pk_seed: bytes, address: Address) -> bytes:
        auth = b''
        for j in range(self.parameter.h_m):
            k = (idx // (2 ** j)) ^ 1
            auth += self.node(sk_seed, k, j, pk_seed, address)

        address = address.with_type(WOTSHashAddress)
        address.keypair = idx
        sig = self.wots.sign(msg, sk_seed, pk_seed, address)
        return sig + auth

    def public_key_from_sign(self, idx: int, sig: bytes, msg: bytes, pk_seed: bytes, address: Address) -> bytes:
        address = address.with_type(WOTSHashAddress)
        address.keypair = idx
        auth = sig[self.parameter.n * self.wots.wots_parameter.len:(
                                                                               self.wots.wots_parameter.len + self.parameter.h_m) * self.parameter.n]
        sig = sig[:self.parameter.n * self.wots.wots_parameter.len]
        node = self.wots.publickey_from_sign(sig, msg, pk_seed, address)
        address = address.with_type(TreeAddress)
        address.index = idx

        for k in range(self.parameter.h_m):
            address.height = k + 1
            if (idx // (2 ** k)) % 2 == 0:
                address.index //= 2
                node = self.parameter.H(pk_seed, address, node + auth[k * self.parameter.n:(k + 1) * self.parameter.n])
            else:
                address.index = (address.index - 1) // 2
                node = self.parameter.H(pk_seed, address, auth[k * self.parameter.n:(k + 1) * self.parameter.n] + node)
        return node
