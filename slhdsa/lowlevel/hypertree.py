from slhdsa.lowlevel.xmss import XMSS
from slhdsa.lowlevel.addresses import Address
from slhdsa.lowlevel.parameters import Parameter
from slhdsa.lowlevel.wots import WOTSParameter


def sign(msg: bytes, sk_seed: bytes, pk_seed: bytes, tree_idx: int, leaf_idx: int, par: Parameter) -> bytes:
    address = Address(0, tree_idx, 0)
    tree = XMSS(par)
    ht_sign = tmp_sign = tree.sign(msg, sk_seed, leaf_idx, pk_seed, address)
    root = tree.public_key_from_sign(leaf_idx, tmp_sign, msg, pk_seed, address)
    for j in range(1, par.d):
        leaf_idx = tree_idx % (2 ** par.h_m)
        tree_idx >>= par.h_m
        address.layer = j
        address.tree = tree_idx
        tmp_sign = tree.sign(root, sk_seed, leaf_idx, pk_seed, address)
        ht_sign += tmp_sign
        if j < par.d - 1:
            root = tree.public_key_from_sign(leaf_idx, tmp_sign, root, pk_seed, address)
    return ht_sign


def verify(msg: bytes, ht_sign: bytes, pk_seed: bytes, tree_idx: int, leaf_idx: int, pk_root: bytes, par: Parameter) -> bool:
    address = Address(0, tree_idx, 0)
    wots_par = WOTSParameter(par)
    tmp_sign = ht_sign[:(par.h_m + wots_par.len) * par.n]
    tree = XMSS(par)
    node = tree.public_key_from_sign(leaf_idx, tmp_sign, msg, pk_seed, address)

    for j in range(1, par.d):
        leaf_idx = tree_idx % (2 ** par.h_m)
        tree_idx >>= par.h_m
        address.layer = j
        address.tree = tree_idx
        tmp_sign = ht_sign[(par.h_m + wots_par.len) * par.n * j:(par.h_m + wots_par.len) * par.n * (j + 1)]
        node = tree.public_key_from_sign(leaf_idx, tmp_sign, node, pk_seed, address)
    return node == pk_root
