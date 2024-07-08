from dataclasses import dataclass

from slhdsa.lowlevel.parameters import Parameter
from slhdsa.lowlevel.addresses import FORSPrfAddress, FORSTreeAddress, FORSRootsAddress
from slhdsa.lowlevel._utils import base2b


@dataclass
class FORS:
    parameter: Parameter

    def generate_secretkey(self, sk_seed: bytes, pk_seed: bytes, address: FORSTreeAddress, idx: int) -> bytes:
        sk_address = address.with_type(FORSPrfAddress)
        sk_address.keypair = address.keypair
        sk_address.index = idx
        return self.parameter.PRF(pk_seed, sk_seed, sk_address)

    def node(self, sk_seed: bytes, cur: int, dep: int, pk_seed: bytes, address: FORSTreeAddress) -> bytes:
        if dep > self.parameter.a or cur >= self.parameter.k * 2 ** (self.parameter.a - dep):
            return b""
        if dep == 0:
            sk = self.generate_secretkey(sk_seed, pk_seed, address, cur)
            address.height = 0
            address.index = cur
            node = self.parameter.F(pk_seed, address, sk)
        else:
            left_node = self.node(sk_seed, 2 * cur, dep - 1, pk_seed, address)
            right_node = self.node(sk_seed, 2 * cur + 1, dep - 1, pk_seed, address)
            address.height = dep
            address.index = cur
            node = self.parameter.H(pk_seed, address, left_node + right_node)
        return node

    def sign(self, md: bytes, sk_seed: bytes, pk_seed: bytes, address: FORSTreeAddress) -> bytes:
        fors_sign = b""
        indices = base2b(md, self.parameter.a, self.parameter.k)
        for i in range(self.parameter.k):
            fors_sign += self.generate_secretkey(sk_seed, pk_seed, address, i * 2 ** self.parameter.a + indices[i])
            auth = b""
            for j in range(self.parameter.a):
                s = (indices[i] // (2 ** j)) ^ 1
                auth += self.node(sk_seed, i * 2 ** (self.parameter.a - j) + s, j, pk_seed, address)
            fors_sign += auth
        return fors_sign

    def publickey_from_sign(self, fors_sign: bytes, md: bytes, pk_seed: bytes, address: FORSTreeAddress) -> bytes:
        indices = base2b(md, self.parameter.a, self.parameter.k)
        root = b""
        for i in range(self.parameter.k):
            sk = fors_sign[
                 i * (self.parameter.a + 1) * self.parameter.n:(i * (self.parameter.a + 1) + 1) * self.parameter.n]
            address.height = 0
            address.index = i * 2 ** self.parameter.a + indices[i]
            node = self.parameter.F(pk_seed, address, sk)
            auth = fors_sign[(i * (self.parameter.a + 1) + 1) * self.parameter.n:(i + 1) * (
                        self.parameter.a + 1) * self.parameter.n]

            for j in range(self.parameter.a):
                address.height = j + 1
                if (indices[i] // (2 ** j)) % 2 == 0:
                    address.index //= 2
                    node = self.parameter.H(pk_seed, address, node + auth[j * self.parameter.n:(j + 1) * self.parameter.n])
                else:
                    address.index = (address.index - 1) // 2
                    node = self.parameter.H(pk_seed, address, auth[j * self.parameter.n:(j + 1) * self.parameter.n] + node)

            root += node
        fors_pk_address = address.with_type(FORSRootsAddress)
        fors_pk_address.keypair = address.keypair
        return self.parameter.Tl(pk_seed, fors_pk_address, root)
