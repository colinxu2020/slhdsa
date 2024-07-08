from secrets import token_bytes

from slhdsa.lowlevel.parameters import Parameter
from slhdsa.lowlevel.addresses import Address, FORSTreeAddress
from slhdsa.lowlevel.xmss import XMSS
from slhdsa.lowlevel._utils import ceil_div
from slhdsa.lowlevel.fors import FORS
from slhdsa.lowlevel.hypertree import sign as ht_sign, verify as ht_verify
from slhdsa.lowlevel.wots import WOTSParameter


def keygen(par: Parameter) -> tuple[tuple[bytes, bytes, bytes, bytes], tuple[bytes, bytes]]:
    sk_seed = token_bytes(par.n)
    sk_prf = token_bytes(par.n)
    pk_seed = token_bytes(par.n)
    address = Address(par.d - 1, 0, 0)
    pk_root = XMSS(par).node(sk_seed, 0, par.h_m, pk_seed, address)
    return (sk_seed, sk_prf, pk_seed, pk_root), (pk_seed, pk_root)


def sign(msg: bytes, secret_key: tuple[bytes, ...], par: Parameter, randomize: bool = False) -> bytes:
    address = FORSTreeAddress(0, 0)
    sk_seed, sk_prf, pk_seed, pk_root = secret_key
    if randomize:
        opt_rand = token_bytes(par.n)
    else:
        opt_rand = pk_seed
    r = par.PRFmsg(sk_prf, opt_rand, msg)
    sig = r

    digest = par.Hmsg(r, pk_seed, pk_root, msg)
    md = digest[:ceil_div(par.k * par.a, 8)]
    tree_idx = int.from_bytes(
        digest[ceil_div(par.k * par.a, 8):ceil_div(par.k * par.a, 8) + ceil_div(par.h - par.h // par.d, 8)])
    tree_idx %= 2 ** (par.h - par.h // par.d)
    leaf_idx = int.from_bytes(digest[
                             ceil_div(par.k * par.a, 8) + ceil_div(par.h - par.h // par.d, 8):ceil_div(par.k * par.a,
                                                                                                       8) + ceil_div(
                                 par.h - par.h // par.d, 8) + ceil_div(par.h, 8 * par.d)])
    leaf_idx %= 2 ** (par.h // par.d)
    address.tree = tree_idx
    address.keypair = leaf_idx
    fors = FORS(par)
    fors_sign = fors.sign(md, sk_seed, pk_seed, address)
    sig += fors_sign
    fors_pk = fors.publickey_from_sign(fors_sign, md, pk_seed, address)
    ht_sign_ = ht_sign(fors_pk, sk_seed, pk_seed, tree_idx, leaf_idx, par)
    sig += ht_sign_
    return sig


def verify(msg: bytes, sig: bytes, public_key: tuple[bytes, ...], par: Parameter) -> bool:
    if len(sig) != (1 + par.k * (par.a + 1) + par.h + par.d * WOTSParameter(par).len) * par.n:
        return False
    address = FORSTreeAddress(0, 0)
    pk_seed, pk_root = public_key
    r = sig[:par.n]
    fors_sign = sig[par.n:(1 + par.k * (par.a + 1)) * par.n]
    ht_sign_ = sig[(1 + par.k * (par.a + 1)) * par.n:]
    digest = par.Hmsg(r, pk_seed, pk_root, msg)
    md = digest[:ceil_div(par.k * par.a, 8)]
    tree_id = int.from_bytes(
        digest[ceil_div(par.k * par.a, 8):ceil_div(par.k * par.a, 8) + ceil_div(par.h - par.h // par.d, 8)])
    tree_id %= 2 ** (par.h - par.h // par.d)
    leaf_id = int.from_bytes(digest[
                             ceil_div(par.k * par.a, 8) + ceil_div(par.h - par.h // par.d, 8):ceil_div(par.k * par.a,
                                                                                                       8) + ceil_div(
                                 par.h - par.h // par.d, 8) + ceil_div(par.h, 8 * par.d)])
    leaf_id %= 2 ** (par.h // par.d)
    address.tree = tree_id
    address.keypair = leaf_id
    fors = FORS(par)
    fors_pk = fors.publickey_from_sign(fors_sign, md, pk_seed, address)
    #print(fors_pk, fors_sign)
    #fors_pk = b'|\x94\xc3\xf2Sk4\xe8\xca\xbf\xf9\xef\xd9\x1b\xced'
    return ht_verify(fors_pk, ht_sign_, pk_seed, tree_id, leaf_id, pk_root, par)
