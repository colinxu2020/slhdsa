from dataclasses import dataclass

from slhdsa.lowlevel.xmss import XMSS
from slhdsa.lowlevel.addresses import Address
from slhdsa.lowlevel.parameters import Parameter
from slhdsa.lowlevel.wots import WOTSParameter



@dataclass
class HyperTree:
    parameter: Parameter

    def sign(self, msg: bytes, sk_seed: bytes, pk_seed: bytes, tree_idx: int, leaf_idx: int) -> bytes:
        address = Address(0, tree_idx)  # ?
        tree = XMSS(self.parameter)
        ht_sign = tmp_sign = tree.sign(msg, sk_seed, leaf_idx, pk_seed, address)
        root = tree.public_key_from_sign(leaf_idx, tmp_sign, msg, pk_seed, address)
        for j in range(1, self.parameter.d):
            leaf_idx = tree_idx % (2 ** self.parameter.h_m)
            tree_idx >>= self.parameter.h_m
            address.layer = j
            address.tree = tree_idx
            tmp_sign = tree.sign(root, sk_seed, leaf_idx, pk_seed, address)
            ht_sign += tmp_sign
            if j < self.parameter.d - 1:
                root = tree.public_key_from_sign(leaf_idx, tmp_sign, root, pk_seed, address)
        return ht_sign


    def verify(self, msg: bytes, ht_sign: bytes, pk_seed: bytes, tree_idx: int, leaf_idx: int, pk_root: bytes) -> bool:
        address = Address(0, tree_idx)  # ?
        wots_par = WOTSParameter(self.parameter)
        tmp_sign = ht_sign[:(self.parameter.h_m + wots_par.len) * self.parameter.n]
        tree = XMSS(self.parameter)
        node = tree.public_key_from_sign(leaf_idx, tmp_sign, msg, pk_seed, address)

        for j in range(1, self.parameter.d):
            leaf_idx = tree_idx % (2 ** self.parameter.h_m)
            tree_idx >>= self.parameter.h_m
            address.layer = j
            address.tree = tree_idx
            tmp_sign = ht_sign[(self.parameter.h_m + wots_par.len) * self.parameter.n * j:(self.parameter.h_m + wots_par.len) * self.parameter.n * (j + 1)]
            node = tree.public_key_from_sign(leaf_idx, tmp_sign, node, pk_seed, address)
        return node == pk_root
