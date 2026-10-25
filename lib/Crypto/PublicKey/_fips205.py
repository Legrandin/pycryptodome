# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""The internal functions of SLH-DSA (FIPS 205, Sections 4 to 9 and 11).

The names follow FIPS 205, and each function says which algorithm it implements.
A number in a comment at the end of a line is the line of that algorithm.
The differences with the pseudocode:

- the seeds (SK.seed and PK.seed) are kept in a :class:`Context`,
  instead of being passed to every function;
- a message M is a tuple of pieces to concatenate (``Message``);
- signing computes the authentication paths first, all at once, possibly with
  several threads (:func:`ht_sign` and :func:`fors_sign`);
- the integer divisions by a power of 2 are shifts;
- :func:`base_2b` converts X to an integer at once, instead of byte by byte.

The functions that compute most of the hashes are in C (src/slhdsa.c):
the tweakable hash functions (F, H, T_l and PRF), chain (Algorithm 5),
xmss_node (Algorithm 9) and fors_node (Algorithm 15).

Key generation and signing can use several threads (the C functions
release the GIL): they compute the roots of XMSS and FORS subtrees, which are
independent, so each thread computes some of them (see :func:`tree_node_batch`).
"""

from __future__ import annotations

import hmac
from enum import IntEnum
from typing import Callable, NamedTuple, Optional, TypeVar

from Crypto.Hash import HMAC, SHA256, SHA512, SHAKE256
from Crypto.Hash.SHA256 import _load_sha_ni_lib
from Crypto.Signature.pss import MGF1
from Crypto.Util._cpu_features import load_avx2_bmi2_lib
from Crypto.Util._raw_api import (
    c_size_t,
    c_uint8_ptr,
    create_string_buffer,
    get_raw_buffer,
    load_pycryptodome_raw_lib,
)
from Crypto.Util._threads import range_boundaries, run_in_threads
from Crypto.Util._typing import Buffer, Message
from Crypto.Util.number import ceil_div

T = TypeVar("T")

_slhdsa_cdecl = """
    int slhdsa_thash(unsigned family, size_t n, unsigned lg_w,
                     uint8_t *out,
                     const uint8_t *pk_seed,
                     const uint8_t adrs[32],
                     const uint8_t *m, size_t m_len);
    int slhdsa_chain(unsigned family, size_t n, unsigned lg_w,
                     uint8_t *out,
                     const uint8_t *pk_seed,
                     const uint8_t adrs[32],
                     const uint8_t *x,
                     unsigned i, unsigned s);
    int slhdsa_xmss_node(unsigned family, size_t n, unsigned lg_w,
                         uint8_t *out,
                         const uint8_t *sk_seed,
                         const uint8_t *pk_seed,
                         const uint8_t adrs[32],
                         uint32_t i, unsigned z);
    int slhdsa_fors_node(unsigned family, size_t n, unsigned lg_w,
                         uint8_t *out,
                         const uint8_t *sk_seed,
                         const uint8_t *pk_seed,
                         const uint8_t adrs[32],
                         uint32_t i, unsigned z);
    """

_raw_slhdsa_portable_lib = load_pycryptodome_raw_lib("Crypto.PublicKey._slhdsa", _slhdsa_cdecl)

# The same code, with SHA-256 using the Intel SHA extensions
_raw_slhdsa_shani_lib = _load_sha_ni_lib("Crypto.PublicKey._slhdsa_shani", _slhdsa_cdecl)

# The same code, compiled for AVX2 and BMI2, with 4 SHAKE hashes at once
_raw_slhdsa_avx2_bmi2_lib = load_avx2_bmi2_lib("Crypto.PublicKey._slhdsa_avx2_bmi2", _slhdsa_cdecl)

# The implementations used by all SLH-DSA keys, for the SHA2 and the SHAKE parameter sets
_raw_slhdsa_sha2_lib = _raw_slhdsa_shani_lib or _raw_slhdsa_portable_lib
_raw_slhdsa_shake_lib = _raw_slhdsa_avx2_bmi2_lib or _raw_slhdsa_portable_lib

# The hash families, as in src/slhdsa.c
_SHAKE = 0
_SHA2 = 1


def gen_len2(n: int, lg_w: int) -> int:
    """Algorithm 1: len2 (Equation 5.3)"""

    w = 1 << lg_w  # 1
    len1 = (8 * n + lg_w - 1) // lg_w  # 2
    max_checksum = len1 * (w - 1)  # 3
    len2 = 1  # 4
    capacity = w  # 5
    while capacity <= max_checksum:  # 6
        len2 += 1  # 7
        capacity = capacity * w  # 8
    return len2  # 10


class Params(NamedTuple):
    """The values of an SLH-DSA parameter set (FIPS 205, Table 2, or SP 800-230, Table 1).
    The parameter sets themselves are in Crypto.PublicKey.SLHDSA."""

    sha2: bool  # SHA2 (Section 11.2) or SHAKE (Section 11.1)
    n: int  # the length of the hashes, in bytes
    h: int  # the height of the hypertree
    d: int  # the number of layers of the hypertree
    hp: int  # h' = h / d, the height of each XMSS tree
    a: int  # the height of each FORS tree
    k: int  # the number of FORS trees
    lg_w: int  # the bits encoded by each WOTS+ chain
    m: int  # the length of the output of H_msg, in bytes

    @property
    def w(self) -> int:
        # The Winternitz parameter (Equation 5.1)
        return 1 << self.lg_w

    @property
    def len1(self) -> int:
        # Equation 5.2
        return ceil_div(8 * self.n, self.lg_w)

    @property
    def len2(self) -> int:
        # Equation 5.3
        return gen_len2(self.n, self.lg_w)

    @property
    def len(self) -> int:
        # The number of WOTS+ chains (Equation 5.4)
        return self.len1 + self.len2

    @property
    def pk_len(self) -> int:
        return 2 * self.n

    @property
    def sk_len(self) -> int:
        return 4 * self.n

    @property
    def sig_len(self) -> int:
        # R, the FORS signature, and d XMSS signatures (Section 9.2, and Algorithm 20, line 1)
        return (1 + self.k * (1 + self.a) + self.h + self.d * self.len) * self.n


def toByte(x: int, n: int) -> bytes:
    """Algorithm 3"""
    return x.to_bytes(n, "big")


def toInt(X: Buffer) -> int:
    """Algorithm 2"""
    return int.from_bytes(X, "big")


def base_2b(X: bytes, b: int, out_len: int) -> list[int]:
    """Algorithm 4: the first out_len integers of b bits in X
    (X read as a big-endian number, from its most significant bits).
    Not line by line: X is converted to an integer at once."""

    used = ceil_div(b * out_len, 8)  # the bytes of X that are read
    if len(X) < used:
        raise ValueError("X is too short")
    # The first b * out_len bits of X, without the bits left over in the last byte
    total = int.from_bytes(X[:used], "big") >> (8 * used - b * out_len)
    mask = (1 << b) - 1
    # The first integer is in the most significant bits
    return [(total >> (b * i)) & mask for i in reversed(range(out_len))]


# Addresses (Sections 4.2 and 4.3)


class AddressType(IntEnum):
    """The address types (Section 4.2), as in src/slhdsa.c"""

    WOTS_HASH = 0
    WOTS_PK = 1
    TREE = 2
    FORS_TREE = 3
    FORS_ROOTS = 4
    WOTS_PRF = 5
    FORS_PRF = 6


class ADRS:
    """An address (Section 4.2), with the member functions of Table 1
    (with the same names: setTypeAndClear() is set_type_and_clear(), etc.).

    The layer address, the tree address and the type are in every address.
    The last 12 bytes depend on the type: each setter below says for which
    types its field exists (FIPS 205 does not check it, and neither does this class).
    Some fields share the same bytes: the chain address and the tree height,
    the hash address and the tree index."""

    # The address types, as in FIPS 205 (ADRS.WOTS_HASH is AddressType.WOTS_HASH)
    WOTS_HASH = AddressType.WOTS_HASH
    WOTS_PK = AddressType.WOTS_PK
    TREE = AddressType.TREE
    FORS_TREE = AddressType.FORS_TREE
    FORS_ROOTS = AddressType.FORS_ROOTS
    WOTS_PRF = AddressType.WOTS_PRF
    FORS_PRF = AddressType.FORS_PRF

    def __init__(self) -> None:
        self._adrs = bytearray(32)

    def copy(self) -> ADRS:
        clone = ADRS()
        clone._adrs[:] = self._adrs
        return clone

    def __bytes__(self) -> bytes:
        return bytes(self._adrs)

    def set_layer_address(self, layer: int) -> None:
        # layer = 0 .. d-1
        self._adrs[0:4] = toByte(layer, 4)

    def set_tree_address(self, tree: int) -> None:
        # tree = 0 .. 2^((d-1-L)*h')-1
        self._adrs[4:16] = toByte(tree, 12)

    def set_type_and_clear(self, address_type: AddressType) -> None:
        """Any type. The last 12 bytes become zero."""
        self._adrs[16:20] = toByte(address_type, 4)
        self._adrs[20:32] = toByte(0, 12)

    def set_key_pair_address(self, i: int) -> None:
        """All types but TREE (where these bytes are padding)"""
        self._adrs[20:24] = toByte(i, 4)

    def set_chain_address(self, i: int) -> None:
        """WOTS_HASH and WOTS_PRF (the same bytes as the tree height)"""
        self._adrs[24:28] = toByte(i, 4)

    def set_tree_height(self, z: int) -> None:
        """TREE, FORS_TREE and FORS_PRF (always 0 for FORS_PRF);
        the same bytes as the chain address"""
        self._adrs[24:28] = toByte(z, 4)

    def set_hash_address(self, i: int) -> None:
        """WOTS_HASH and WOTS_PRF (always 0 for WOTS_PRF);
        the same bytes as the tree index"""
        self._adrs[28:32] = toByte(i, 4)

    def set_tree_index(self, i: int) -> None:
        """TREE, FORS_TREE and FORS_PRF (the same bytes as the hash address)"""
        self._adrs[28:32] = toByte(i, 4)

    def get_key_pair_address(self) -> int:
        """All types but TREE (see set_key_pair_address)"""
        return toInt(self._adrs[20:24])

    def get_tree_index(self) -> int:
        """TREE, FORS_TREE and FORS_PRF (see set_tree_index)"""
        return toInt(self._adrs[28:32])


# The hash functions (Section 11)


class Context:
    """The hash functions (Section 11) for a key: PK.seed, and SK.seed
    if the private key is needed (for PRF, xmss_node and fors_node).

    F, H, T_l and PRF are SHAKE256(PK.seed || ADRS || M, 8n) (Section 11.1), or
    Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRS^c || M)) (Section 11.2),
    except that H and T_l use SHA-512 and toByte(0, 128 - n) for n > 16
    (Section 11.2.2). They are in C (src/slhdsa.c).
    The methods take the same parameters as in FIPS 205, without PK.seed and SK.seed."""

    def __init__(self, params: Params, pk_seed: bytes, sk_seed: Optional[bytes] = None) -> None:
        # The C code reads n bytes from PK.seed and SK.seed
        if len(pk_seed) != params.n:
            raise ValueError("PK.seed must be %d bytes long" % params.n)
        if sk_seed is not None and len(sk_seed) != params.n:
            raise ValueError("SK.seed must be %d bytes long" % params.n)
        self.params = params
        self.pk_seed = pk_seed
        self.sk_seed = sk_seed
        self._family = _SHA2 if params.sha2 else _SHAKE
        self._lib = _raw_slhdsa_sha2_lib if params.sha2 else _raw_slhdsa_shake_lib
        # The hash function of H_msg and PRF_msg for SHA2 (Sections 11.2.1 and 11.2.2)
        self._sha2 = SHA256 if params.n == 16 else SHA512

    def _check(self, result: int, name: str) -> None:
        if result:
            raise ValueError("Error %d in SLH-DSA (%s)" % (result, name))

    def _thash(self, adrs: ADRS, M: bytes) -> bytes:
        n = self.params.n
        out = create_string_buffer(n)
        result = self._lib.slhdsa_thash(
            self._family,
            c_size_t(n),
            self.params.lg_w,
            out,
            c_uint8_ptr(self.pk_seed),
            c_uint8_ptr(bytes(adrs)),
            c_uint8_ptr(M),
            c_size_t(len(M)),
        )
        self._check(result, "thash")
        return get_raw_buffer(out)

    def F(self, adrs: ADRS, M1: bytes) -> bytes:
        """F(PK.seed, ADRS, M_1)"""
        assert len(M1) == self.params.n
        return self._thash(adrs, M1)

    def H(self, adrs: ADRS, M2: bytes) -> bytes:
        """H(PK.seed, ADRS, M_2)"""
        assert len(M2) == 2 * self.params.n
        return self._thash(adrs, M2)

    def T(self, adrs: ADRS, M: bytes) -> bytes:
        """T_l(PK.seed, ADRS, M_l), with l = len(M) / n (the C code checks it)"""
        return self._thash(adrs, M)

    def PRF(self, adrs: ADRS) -> bytes:
        """PRF(PK.seed, SK.seed, ADRS), which is F(PK.seed, ADRS, SK.seed)"""
        assert self.sk_seed is not None
        return self._thash(adrs, self.sk_seed)

    def H_msg(self, R: bytes, pk_root: bytes, M: Message) -> bytes:
        """H_msg(R, PK.seed, PK.root, M):
        SHAKE256(R || PK.seed || PK.root || M, 8m) (Section 11.1), or
        MGF1-SHA-x(R || PK.seed || SHA-x(R || PK.seed || PK.root || M), m),
        with SHA-256 for n = 16 (Section 11.2.1) and SHA-512 otherwise (Section 11.2.2)"""

        if not self.params.sha2:
            shake = SHAKE256.new(R + self.pk_seed + pk_root)
            for piece in M:
                shake.update(piece)
            return shake.read(self.params.m)

        h = self._sha2.new(R + self.pk_seed + pk_root)
        for piece in M:
            h.update(piece)
        return MGF1(R + self.pk_seed + h.digest(), self.params.m, self._sha2)

    def PRF_msg(self, sk_prf: bytes, opt_rand: bytes, M: Message) -> bytes:
        """PRF_msg(SK.prf, opt_rand, M):
        SHAKE256(SK.prf || opt_rand || M, 8n) (Section 11.1), or
        Trunc_n(HMAC-SHA-x(SK.prf, opt_rand || M)), with SHA-256 for n = 16
        (Section 11.2.1) and SHA-512 otherwise (Section 11.2.2)"""

        n = self.params.n
        if not self.params.sha2:
            shake = SHAKE256.new(sk_prf + opt_rand)
            for piece in M:
                shake.update(piece)
            return shake.read(n)

        mac = HMAC.new(sk_prf, opt_rand, digestmod=self._sha2)
        for piece in M:
            mac.update(piece)
        return mac.digest()[:n]

    def chain(self, X: bytes, i: int, s: int, adrs: ADRS) -> bytes:
        """Algorithm 5 (ADRS is not modified)"""

        n = self.params.n
        if len(X) != n:  # the C code reads n bytes from X
            raise ValueError("X must be %d bytes long" % n)
        out = create_string_buffer(n)
        result = self._lib.slhdsa_chain(
            self._family,
            c_size_t(n),
            self.params.lg_w,
            out,
            c_uint8_ptr(self.pk_seed),
            c_uint8_ptr(bytes(adrs)),
            c_uint8_ptr(X),
            i,
            s,
        )
        self._check(result, "chain")
        return get_raw_buffer(out)

    def xmss_node(self, i: int, z: int, adrs: ADRS) -> bytes:
        """Algorithm 9 (ADRS is not modified)"""
        return self._node(self._lib.slhdsa_xmss_node, i, z, adrs)

    def fors_node(self, i: int, z: int, adrs: ADRS) -> bytes:
        """Algorithm 15 (ADRS is not modified)"""
        return self._node(self._lib.slhdsa_fors_node, i, z, adrs)

    def _node(self, func, i: int, z: int, adrs: ADRS) -> bytes:
        n = self.params.n
        assert self.sk_seed is not None
        out = create_string_buffer(n)
        result = func(
            self._family,
            c_size_t(n),
            self.params.lg_w,
            out,
            c_uint8_ptr(self.sk_seed),
            c_uint8_ptr(self.pk_seed),
            c_uint8_ptr(bytes(adrs)),
            i,
            z,
        )
        self._check(result, "node")
        return get_raw_buffer(out)


# Minimum number of hashes that each thread must compute (about 64 XMSS leaves
# of the FIPS 205 parameter sets): with fewer, starting the thread costs more
# than what it saves.
_MIN_HASHES_PER_THREAD = 32768


def useful_threads(threads: int, hashes: int) -> int:
    """The number of threads worth using (at most ``threads``) for computing
    about ``hashes`` hashes."""
    return max(1, min(threads, hashes // _MIN_HASHES_PER_THREAD))


def parallel_map(func: Callable[[int], T], count: int, threads: int) -> list[T]:
    """Return ``[func(0), ..., func(count - 1)]``, computed by up to ``threads``
    threads, each one on a range of consecutive values.
    ``func`` must not change anything shared with the other calls."""

    threads = min(threads, count)
    if threads <= 1:
        return [func(i) for i in range(count)]

    bounds = range_boundaries(count, threads)

    def worker(t: int) -> list[T]:
        return [func(i) for i in range(bounds[t], bounds[t + 1])]

    return [result for part in run_in_threads(worker, threads) for result in part]


# The subtrees per thread: with several of them, the threads finish at about
# the same time, even if the number of subtrees is not a multiple of the threads.
_SUBTREES_PER_THREAD = 4


def tree_node_batch(
    ctx: Context,
    node: Callable[[int, int, ADRS], bytes],
    leaf_hashes: int,
    targets: list[tuple[int, int, ADRS, ADRS]],
    threads: int,
) -> list[bytes]:
    """xmss_node(i, z, ADRS) (Algorithm 9) or fors_node(i, z, ADRS) (Algorithm 15)
    for several targets at once, with up to ``threads`` threads.

    Each target ``(i, z, ADRS, parent_ADRS)`` is the node i of height z
    (see :func:`xmss_node_batch`) of the tree in ADRS; for FORS, the nodes of
    the k trees are numbered together (the node i is in the tree i >> (a - z)).

    The result is the list of ``node(i, z, ADRS)`` for each target,
    in the same order, where ``node`` is :meth:`Context.xmss_node`
    or :meth:`Context.fors_node`.
    This is how the authentication paths of Algorithms 10 and 16, and PK.root
    (Algorithm 18), are computed.

    ``leaf_hashes`` is about how many hashes one leaf costs: it is only used to
    decide how many threads are worth starting.

    With one thread, each target is one call to ``node``.
    With more threads, each target higher than some height s is split into
    the 2^(z - s) nodes of height s below it, and all the nodes of height
    at most s are computed in parallel (``node`` is in C, and releases the GIL).
    s is the largest height that gives at least _SUBTREES_PER_THREAD nodes per thread.
    Then the z - s levels above them are hashed with H in Python, as Algorithms 9
    and 15 do for z > 0. These hashes use parent_ADRS, the address of the inner
    nodes (type TREE for XMSS, FORS_TREE for FORS): its tree height and tree index
    are overwritten. ADRS is not modified."""

    leaves = sum(1 << z for _, z, _, _ in targets)
    threads = useful_threads(threads, leaves * leaf_hashes)

    def split_nodes(s: int) -> int:
        return sum(1 << max(z - s, 0) for _, z, _, _ in targets)

    # s: the height at which the targets are split into jobs (one call to node() each)
    s = max(z for _, z, _, _ in targets)
    while threads > 1 and s > 0 and split_nodes(s) < threads * _SUBTREES_PER_THREAD:
        s -= 1

    # One job per node of height at most s: (its target, node index, its height).
    # Nodes for each height are numbered from left to right, starting at 0.
    # Node i at height z covers the leaves i·2^z to (i + 1)·2^z - 1.
    # Its descendants at height h are therefore the 2^(z - h) consecutive nodes
    # that start at i·2^(z - h).
    jobs = []
    for target_nr, (node_index, z, _, _) in enumerate(targets):
        height = min(z, s)
        for j in range(1 << (z - height)):
            job = target_nr, (node_index << (z - height)) + j, height
            jobs.append(job)

    def subtree(job_nr: int) -> bytes:
        target_nr, node_index, height = jobs[job_nr]
        return node(node_index, height, targets[target_nr][2])

    nodes = parallel_map(subtree, len(jobs), threads)

    # The threads have hashed the subtrees; now hash with Python to obtain
    # one value per target. nodes[] contains consecutive sequences
    # of nodes for the same target. A sequence has 1 << (z - min(z, s)) nodes
    # where z is the original height of each target.
    result = []
    first_job = 0
    for node_index, z, _, parent_adrs in targets:
        # Nodes of a target that need to be hashed together
        level = nodes[first_job : first_job + (1 << (z - min(z, s)))]
        first_job += len(level)

        # One level at a time, going upwards
        for height in range(min(z, s) + 1, z + 1):
            parent_adrs.set_tree_height(height)

            # Build the level above
            parents = []
            first = node_index << (z - height)

            for j in range(len(level) // 2):
                parent_adrs.set_tree_index(first + j)
                parent_node = ctx.H(parent_adrs, level[2 * j] + level[2 * j + 1])
                parents.append(parent_node)
            level = parents

        # The final level has one node only: the target
        result.append(level[0])

    return result


# WOTS+ (Section 5)


def wots_digits(ctx: Context, M: bytes) -> list[int]:
    """The base-w digits of the message M and of its checksum
    (Algorithm 7, lines 1 to 7, which Algorithm 8 repeats)"""

    p = ctx.params
    csum = 0  # 1
    msg = base_2b(M, p.lg_w, p.len1)  # 2
    for i in range(p.len1):  # 3
        csum = csum + p.w - 1 - msg[i]  # 4
    csum = csum << ((8 - ((p.len2 * p.lg_w) % 8)) % 8)  # 6
    msg = msg + base_2b(toByte(csum, ceil_div(p.len2 * p.lg_w, 8)), p.lg_w, p.len2)  # 7
    return msg


def wots_sign(ctx: Context, M: bytes, adrs: ADRS) -> bytes:
    """Algorithm 7"""

    p = ctx.params
    msg = wots_digits(ctx, M)  # 1 to 7
    sk_adrs = adrs.copy()  # 8
    sk_adrs.set_type_and_clear(ADRS.WOTS_PRF)  # 9
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address())  # 10
    sig = []
    for i in range(p.len):  # 11
        sk_adrs.set_chain_address(i)  # 12
        sk = ctx.PRF(sk_adrs)  # 13
        adrs.set_chain_address(i)  # 14
        sig.append(ctx.chain(sk, 0, msg[i], adrs))  # 15
    return b"".join(sig)  # 17


def wots_pkFromSig(ctx: Context, sig: bytes, M: bytes, adrs: ADRS) -> bytes:
    """Algorithm 8"""

    p = ctx.params
    n = p.n
    msg = wots_digits(ctx, M)  # 1 to 7
    tmp = []
    for i in range(p.len):  # 8
        adrs.set_chain_address(i)  # 9
        tmp.append(ctx.chain(sig[i * n : (i + 1) * n], msg[i], p.w - 1 - msg[i], adrs))  # 10
    wotspk_adrs = adrs.copy()  # 12
    wotspk_adrs.set_type_and_clear(ADRS.WOTS_PK)  # 13
    wotspk_adrs.set_key_pair_address(adrs.get_key_pair_address())  # 14
    pk_sig = ctx.T(wotspk_adrs, b"".join(tmp))  # 15
    return pk_sig  # 16


# XMSS (Section 6)


def xmss_node_batch(ctx: Context, targets: list[tuple[int, int, ADRS]], threads: int) -> list[bytes]:
    """xmss_node(i, z, ADRS) (Algorithm 9) for each (i, z, ADRS) in ``targets``,
    with up to ``threads`` threads (see :func:`tree_node_batch`).
    i is the index of the node among the 2^(h' - z) nodes of height z of the tree:
    the node i of height z is the root of the subtree with the leaves
    i * 2^z to (i + 1) * 2^z - 1. The ADRS are not modified."""

    p = ctx.params
    tree_targets = []
    for i, z, adrs in targets:
        # The inner nodes are hashed with an address of type TREE (Algorithm 9)
        parent_adrs = adrs.copy()
        parent_adrs.set_type_and_clear(ADRS.TREE)
        tree_targets.append((i, z, adrs, parent_adrs))
    # The cost of a leaf: a leaf is a WOTS+ public key, made of len chains,
    # each of them 1 PRF (for its private value) and w - 1 F (Algorithm 6)
    return tree_node_batch(ctx, ctx.xmss_node, p.len * p.w, tree_targets, threads)


def xmss_sign(ctx: Context, M: bytes, idx: int, adrs: ADRS, auth: bytes) -> bytes:
    """Algorithm 10, with AUTH (lines 1 to 4) computed in advance (see :func:`ht_sign`)"""

    adrs.set_type_and_clear(ADRS.WOTS_HASH)  # 5
    adrs.set_key_pair_address(idx)  # 6
    sig = wots_sign(ctx, M, adrs)  # 7
    sig_xmss = sig + auth  # 8
    return sig_xmss  # 9


def climb_auth_path(ctx: Context, idx: int, node: bytes, auth: bytes, adrs: ADRS) -> bytes:
    """Lines 8 to 18 of Algorithms 11 and 17: hash node, the leaf idx of its tree,
    up to the root with the authentication path auth (ADRS has the tree index of the leaf)"""

    n = ctx.params.n

    # node[0] of FIPS 205 is node, and node[1] the next value of node
    for k in range(len(auth) // n):  # 8
        auth_k = auth[k * n : (k + 1) * n]
        adrs.set_tree_height(k + 1)  # 9
        if (idx >> k) % 2 == 0:  # 10
            adrs.set_tree_index(adrs.get_tree_index() // 2)  # 11
            node = ctx.H(adrs, node + auth_k)  # 12, 17
        else:
            adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)  # 14
            node = ctx.H(adrs, auth_k + node)  # 15, 17
    return node


def xmss_pkFromSig(ctx: Context, idx: int, sig_xmss: bytes, M: bytes, adrs: ADRS) -> bytes:
    """Algorithm 11"""

    p = ctx.params
    n = p.n

    adrs.set_type_and_clear(ADRS.WOTS_HASH)  # 1
    adrs.set_key_pair_address(idx)  # 2
    sig = sig_xmss[: p.len * n]  # 3
    auth = sig_xmss[p.len * n : (p.len + p.hp) * n]  # 4
    node = wots_pkFromSig(ctx, sig, M, adrs)  # 5

    adrs.set_type_and_clear(ADRS.TREE)  # 6
    adrs.set_tree_index(idx)  # 7
    return climb_auth_path(ctx, idx, node, auth, adrs)  # 8 to 19


# The hypertree (Section 7)


def ht_sign(ctx: Context, M: bytes, idx_tree: int, idx_leaf: int, threads: int = 1) -> bytes:
    """Algorithm 12.

    The authentication paths (Algorithm 10, lines 1 to 4), which take nearly
    all the time, do not depend on the messages that each layer signs:
    they are computed first, all at once, with up to ``threads`` threads.
    Then each layer signs the root of the layer below, in order.
    Layer 0 (lines 1 to 5) is the first iteration of the loop of lines 6 to 16."""

    p = ctx.params

    # idx_tree and idx_leaf in each layer j (lines 7 and 8)
    trees = [idx_tree]
    leaves = [idx_leaf]
    for _ in range(1, p.d):
        leaves.append(trees[-1] % (1 << p.hp))  # 7
        trees.append(trees[-1] >> p.hp)  # 8

    def layer_adrs(j: int) -> ADRS:
        adrs = ADRS()  # 1
        adrs.set_layer_address(j)  # 9
        adrs.set_tree_address(trees[j])  # 2, 10
        return adrs

    # AUTH of each layer: the nodes k = floor(idx / 2^z) xor 1 of each height z
    # from 0 to h' - 1 (Algorithm 10, lines 1 to 4)
    targets = [((leaves[j] >> z) ^ 1, z, layer_adrs(j)) for j in range(p.d) for z in range(p.hp)]
    nodes = xmss_node_batch(ctx, targets, threads)
    auth = [b"".join(nodes[j * p.hp : (j + 1) * p.hp]) for j in range(p.d)]

    sig_ht = []
    root = M
    for j in range(p.d):  # 6
        adrs = layer_adrs(j)
        sig_tmp = xmss_sign(ctx, root, leaves[j], adrs, auth[j])  # 3, 11
        sig_ht.append(sig_tmp)  # 4, 12
        if j < p.d - 1:  # 13
            root = xmss_pkFromSig(ctx, leaves[j], sig_tmp, root, adrs)  # 5, 14
    return b"".join(sig_ht)  # 17


def ht_verify(ctx: Context, M: bytes, sig_ht: bytes, idx_tree: int, idx_leaf: int, pk_root: bytes) -> bool:
    """Algorithm 13"""

    p = ctx.params
    xmss_len = (p.hp + p.len) * p.n
    adrs = ADRS()  # 1
    adrs.set_tree_address(idx_tree)  # 2
    sig_tmp = sig_ht[:xmss_len]  # 3
    node = xmss_pkFromSig(ctx, idx_leaf, sig_tmp, M, adrs)  # 4
    for j in range(1, p.d):  # 5
        idx_leaf = idx_tree % (1 << p.hp)  # 6
        idx_tree = idx_tree >> p.hp  # 7
        adrs.set_layer_address(j)  # 8
        adrs.set_tree_address(idx_tree)  # 9
        sig_tmp = sig_ht[j * xmss_len : (j + 1) * xmss_len]  # 10
        node = xmss_pkFromSig(ctx, idx_leaf, sig_tmp, node, adrs)  # 11
    return hmac.compare_digest(node, pk_root)  # 13 to 17


# FORS (Section 8)


def fors_skGen(ctx: Context, adrs: ADRS, idx: int) -> bytes:
    """Algorithm 14"""

    sk_adrs = adrs.copy()  # 1
    sk_adrs.set_type_and_clear(ADRS.FORS_PRF)  # 2
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address())  # 3
    sk_adrs.set_tree_index(idx)  # 4
    return ctx.PRF(sk_adrs)  # 5


def fors_sign(ctx: Context, md: bytes, adrs: ADRS, threads: int = 1) -> bytes:
    """Algorithm 16 (ADRS is not modified).

    The authentication paths of the k trees are computed all at once,
    with up to ``threads`` threads."""

    p = ctx.params

    # The message digest to sign (md) is split into k a-bit strings.
    # Each string is interpreted as an integer 0..t = 0..2^a-1,
    # to be used as index in the array of t secrets.
    indices = base_2b(md, p.a, p.k)  # 2

    # AUTH = authentication path of one of the FORS trees (there are k trees,
    # all of height a). It is the siblings of each node on the way up from
    # the leaf to the root. Each sibling is also n bytes.
    # At height 0 you have the t hashes of the t secrets.

    # AUTH of each tree i (lines 5 to 8). The inner nodes are hashed with
    # an address of the same type as the leaves (FORS_TREE, Algorithm 15).
    targets = []
    for i in range(p.k):
        for j in range(p.a):  # 5
            s = (indices[i] >> j) ^ 1  # 6
            target = (i << (p.a - j)) + s, j, adrs, adrs.copy()  # 7
            targets.append(target)  # 7

    # The cost of a leaf: 1 PRF (its private value) and 1 F (Algorithm 15),
    # plus about 1 H for its share of the nodes above it
    nodes = tree_node_batch(ctx, ctx.fors_node, 3, targets, threads)

    sig_fors = []  # 1
    for i in range(p.k):  # 3
        sig_fors.append(fors_skGen(ctx, adrs, (i << p.a) + indices[i]))  # 4
        sig_fors += nodes[i * p.a : (i + 1) * p.a]  # 9
    return b"".join(sig_fors)  # 11


def fors_pkFromSig(ctx: Context, sig_fors: bytes, md: bytes, adrs: ADRS) -> bytes:
    """Algorithm 17"""

    p = ctx.params
    n = p.n
    a = p.a

    indices = base_2b(md, a, p.k)  # 1
    root = []
    for i in range(p.k):  # 2
        # For each tree, SIG_FORS has sk and then AUTH: a + 1 values of n bytes
        sig_tree = sig_fors[i * (a + 1) * n : (i + 1) * (a + 1) * n]
        sk = sig_tree[:n]  # 3
        auth = sig_tree[n:]  # 7
        adrs.set_tree_height(0)  # 4
        adrs.set_tree_index((i << a) + indices[i])  # 5
        node = ctx.F(adrs, sk)  # 6
        node = climb_auth_path(ctx, indices[i], node, auth, adrs)  # 8 to 18
        root.append(node)  # 19

    forspk_adrs = adrs.copy()  # 21
    forspk_adrs.set_type_and_clear(ADRS.FORS_ROOTS)  # 22
    forspk_adrs.set_key_pair_address(adrs.get_key_pair_address())  # 23
    pk = ctx.T(forspk_adrs, b"".join(root))  # 24
    return pk  # 25


# SLH-DSA (Section 9)


def slh_keygen_internal(
    params: Params, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes, threads: int = 1
) -> tuple[bytes, bytes]:
    """Algorithm 18: return the private key and the public key"""

    ctx = Context(params, pk_seed, sk_seed)
    adrs = ADRS()  # 1
    adrs.set_layer_address(params.d - 1)  # 2
    pk_root = xmss_node_batch(ctx, [(0, params.hp, adrs)], threads)[0]  # 3: xmss_node(0, h', ADRS)
    return sk_seed + sk_prf + pk_seed + pk_root, pk_seed + pk_root  # 4


def split_digest(params: Params, digest: bytes) -> tuple[bytes, int, int]:
    """Split the output of H_msg into md, idx_tree and idx_leaf
    (Algorithm 19, lines 6 to 10, which are lines 9 to 13 of Algorithm 20).
    h/d of FIPS 205 is h'."""

    md_len = ceil_div(params.k * params.a, 8)  # ceil(k*a / 8)
    tree_len = ceil_div(params.h - params.hp, 8)  # ceil((h - h/d) / 8)
    leaf_len = ceil_div(params.hp, 8)  # ceil(h / 8d)

    md = digest[:md_len]  # 6
    tmp_idx_tree = digest[md_len : md_len + tree_len]  # 7
    tmp_idx_leaf = digest[md_len + tree_len : md_len + tree_len + leaf_len]  # 8

    idx_tree = toInt(tmp_idx_tree) % (1 << (params.h - params.hp))  # 9
    idx_leaf = toInt(tmp_idx_leaf) % (1 << params.hp)  # 10
    return md, idx_tree, idx_leaf


def slh_sign_internal(
    params: Params, M: Message, SK: bytes, addrnd: Optional[bytes], threads: int = 1
) -> bytes:
    """Algorithm 19. addrnd is None for the deterministic variant."""

    n = params.n
    sk_seed, sk_prf, pk_seed, pk_root = (SK[i * n : (i + 1) * n] for i in range(4))
    ctx = Context(params, pk_seed, sk_seed)

    adrs = ADRS()  # 1
    opt_rand = pk_seed if addrnd is None else addrnd  # 2
    R = ctx.PRF_msg(sk_prf, opt_rand, M)  # 3

    digest = ctx.H_msg(R, pk_root, M)  # 5
    md, idx_tree, idx_leaf = split_digest(params, digest)  # 6 to 10

    adrs.set_tree_address(idx_tree)  # 11
    adrs.set_type_and_clear(ADRS.FORS_TREE)  # 12
    adrs.set_key_pair_address(idx_leaf)  # 13
    sig_fors = fors_sign(ctx, md, adrs, threads)  # 14
    pk_fors = fors_pkFromSig(ctx, sig_fors, md, adrs)  # 16
    sig_ht = ht_sign(ctx, pk_fors, idx_tree, idx_leaf, threads)  # 17
    return R + sig_fors + sig_ht  # 4, 15, 18, 19


def slh_verify_internal(params: Params, M: Message, SIG: bytes, PK: bytes) -> bool:
    """Algorithm 20"""

    n = params.n
    if len(SIG) != params.sig_len:  # 1
        return False  # 2
    pk_seed, pk_root = PK[:n], PK[n:]
    ctx = Context(params, pk_seed)

    k, a = params.k, params.a
    adrs = ADRS()  # 4
    R = SIG[:n]  # 5
    sig_fors = SIG[n : (1 + k * (1 + a)) * n]  # 6
    sig_ht = SIG[(1 + k * (1 + a)) * n :]  # 7

    digest = ctx.H_msg(R, pk_root, M)  # 8
    md, idx_tree, idx_leaf = split_digest(params, digest)  # 9 to 13

    adrs.set_tree_address(idx_tree)  # 14
    adrs.set_type_and_clear(ADRS.FORS_TREE)  # 15
    adrs.set_key_pair_address(idx_leaf)  # 16
    pk_fors = fors_pkFromSig(ctx, sig_fors, md, adrs)  # 17
    return ht_verify(ctx, pk_fors, sig_ht, idx_tree, idx_leaf, pk_root)  # 18
