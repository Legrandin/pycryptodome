# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""Argon2 (RFC 9106), re-exported by :mod:`Crypto.Protocol.KDF`.

The memory-hard part is in C (``Crypto.Protocol._argon2_core``), loaded on the
first call: importing :mod:`Crypto.Protocol.KDF` does not load it.
"""

from __future__ import annotations

import binascii
import enum
import re
import struct
import threading
import warnings
from hmac import compare_digest
from typing import Any, Literal, NamedTuple, Optional, Union, overload

from Crypto import KdfIterationLimitError, KdfMemoryLimitError
from Crypto.Hash import BLAKE2b
from Crypto.Random import get_random_bytes
from Crypto.Util._bytes import tobytes
from Crypto.Util._raw_api import (
    VoidPointer,
    c_uint8_ptr,
    create_string_buffer,
    get_raw_buffer,
    is_buffer,
    load_pycryptodome_raw_lib,
)
from Crypto.Util._threads import range_boundaries, run_in_threads, threads_param
from Crypto.Util._typing import Buffer

__all__ = [
    "ARGON2_DEFAULT_PROFILE",
    "Argon2Params",
    "Argon2Profile",
    "Argon2Variant",
    "argon2",
    "argon2_check",
    "argon2_hash",
]


class Argon2Variant(str, enum.Enum):
    """The variants of Argon2. Each value is the identifier of the variant
    in a PHC string (for instance, ``$argon2id$...``).

    Use :attr:`ARGON2ID`, unless you have a specific reason for another one.
    """

    #: The memory accesses depend on the password.
    #: The most resistant to GPU and ASIC attacks, but it leaks information
    #: through cache timing, so only use it where an attacker cannot run
    #: code on the same machine.
    ARGON2D = "argon2d"
    #: The memory accesses do not depend on the password.
    #: It resists cache-timing attacks, but it is weaker against
    #: time-memory trade-offs.
    ARGON2I = "argon2i"
    #: Like Argon2i for the first half of the first pass, then like Argon2d.
    #: The variant recommended by RFC 9106 (it must be supported by every implementation).
    ARGON2ID = "argon2id"


# The type y of RFC 9106, for each variant
_TYPE = {Argon2Variant.ARGON2D: 0, Argon2Variant.ARGON2I: 1, Argon2Variant.ARGON2ID: 2}


class Argon2Params(NamedTuple):
    """The parameters of a profile of Argon2 (see :class:`Argon2Profile`)."""

    #: The variant
    variant: Argon2Variant
    #: The number of passes over the memory (*t*)
    time_cost: int
    #: The memory, in KiB (*m*)
    memory_cost: int
    #: The degree of parallelism, that is the number of lanes (*p*)
    lanes: int
    #: The recommended length of the salt, in bytes
    salt_len: int
    #: The recommended length of the key or tag, in bytes
    key_len: int
    #: The document that recommends these parameters
    source: str
    #: The year of that recommendation
    year: int
    #: What the parameters are for
    rationale: str
    #: Why the profile should no longer be used for new hashes (``None`` if it can)
    deprecated: Optional[str] = None


@enum.unique
class Argon2Profile(Argon2Params, enum.Enum):
    """Named, published sets of parameters for Argon2.

    Each member is an :class:`Argon2Params`, so its parameters are attributes
    (for instance, ``Argon2Profile.RFC9106_2021_64MIB.time_cost`` is 3).

    A profile never changes and is never removed: the same profile always
    derives the same key, in every version of this library.
    The name of each member says where the parameters come from,
    and when they were published.
    """

    #: The first recommended option of RFC 9106 (Section 4), "uniformly safe",
    #: where 2 GiB for each derivation are affordable (file encryption, offline keys).
    RFC9106_2021_2GIB = (
        Argon2Variant.ARGON2ID,
        1,
        2 * 1024 * 1024,
        4,
        16,
        32,
        "RFC 9106, Section 4, first recommended option (https://www.rfc-editor.org/rfc/rfc9106#section-4)",
        2021,
        "A uniformly safe option, when 2 GiB of memory can be used for each derivation",
    )
    #: The second recommended option of RFC 9106 (Section 4), when much less memory
    #: is available. The default of :func:`argon2_hash`.
    RFC9106_2021_64MIB = (
        Argon2Variant.ARGON2ID,
        3,
        64 * 1024,
        4,
        16,
        32,
        "RFC 9106, Section 4, second recommended option (https://www.rfc-editor.org/rfc/rfc9106#section-4)",
        2021,
        "A uniformly safe option, when much less memory is available",
    )
    #: The minimum of the OWASP Password Storage Cheat Sheet, for a login server
    #: that must handle many logins at once.
    OWASP_2023_19MIB = (
        Argon2Variant.ARGON2ID,
        2,
        19 * 1024,
        1,
        16,
        32,
        "OWASP Password Storage Cheat Sheet, January 2023 "
        "(https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id)",
        2023,
        "The minimum for password storage on a server with many concurrent logins",
    )
    #: The ``crypto_pwhash_argon2id_*_INTERACTIVE`` limits of libsodium (1.0.13), for online logins.
    LIBSODIUM_2017_INTERACTIVE = (
        Argon2Variant.ARGON2ID,
        2,
        64 * 1024,
        1,
        16,
        32,
        "libsodium 1.0.13, crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE and MEMLIMIT_INTERACTIVE "
        "(https://doc.libsodium.org/password_hashing/default_phf)",
        2017,
        "Interactive, online operations (logins)",
    )
    #: The ``crypto_pwhash_argon2id_*_MODERATE`` limits of libsodium (1.0.13).
    LIBSODIUM_2017_MODERATE = (
        Argon2Variant.ARGON2ID,
        3,
        256 * 1024,
        1,
        16,
        32,
        "libsodium 1.0.13, crypto_pwhash_argon2id_OPSLIMIT_MODERATE and MEMLIMIT_MODERATE "
        "(https://doc.libsodium.org/password_hashing/default_phf)",
        2017,
        "A compromise between interactive and sensitive operations",
    )
    #: The ``crypto_pwhash_argon2id_*_SENSITIVE`` limits of libsodium (1.0.13),
    #: for highly sensitive data and non-interactive operations.
    LIBSODIUM_2017_SENSITIVE = (
        Argon2Variant.ARGON2ID,
        4,
        1024 * 1024,
        1,
        16,
        32,
        "libsodium 1.0.13, crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE and MEMLIMIT_SENSITIVE "
        "(https://doc.libsodium.org/password_hashing/default_phf)",
        2017,
        "Highly sensitive data, non-interactive operations",
    )


#: The profile that :func:`argon2_hash` uses when it gets no profile and no costs.
#: It may change in a future release (hashes store their own parameters).
ARGON2_DEFAULT_PROFILE = Argon2Profile.RFC9106_2021_64MIB


_VERSION = 0x13
_MAX_U32 = 2**32 - 1
_MAX_LANES = 2**24 - 1
_MIN_SALT_LEN = 8
_MIN_TAG_LEN = 4
_SYNC_POINTS = 4
_BLOCK_SIZE = 1024

#: Default maximum work of a hash in argon2_check() (max_cost is None):
#: passes times memory (in KiB), about one minute on one thread of a recent laptop
_DEFAULT_MAX_ARGON2_COST = 2**25

_MEMORY_ERROR = (
    "The Argon2 hash needs {memory} bytes of memory, above the maximum allowed by "
    "max_memory: {limit}. If you trust the hash, increase max_memory "
    "(or set it to 0 to disable the check)."
)
_COST_ERROR = (
    "The Argon2 hash has a cost (passes times memory in KiB) of {cost}, above the "
    "maximum allowed by max_cost: {limit}. If you trust the hash, increase max_cost "
    "(or set it to 0 to disable the check)."
)

_ARGON2_CDECL = """
    int argon2_new(void **state, uint32_t blocks, uint32_t lanes,
                   uint32_t passes, uint32_t type);
    int argon2_destroy(void *state);
    int argon2_set_block(void *state, uint32_t lane, uint32_t index,
                         const uint8_t *in);
    int argon2_fill_segment(void *state, uint32_t pass, uint32_t slice,
                            uint32_t lane);
    int argon2_get_final_block(const void *state, uint8_t *out);
    """

#: The C implementations that this machine can run, by name, loaded on the
#: first call to _lib(): "portable" (which uses SSE2 on x86-64), and
#: "avx2_bmi2" on a CPU with AVX2, BMI1 and BMI2
_raw_argon2_libs: dict[str, Any] = {}

#: The implementation in use: the fastest one
_raw_argon2_lib: Any = None
_raw_argon2_lock = threading.Lock()


def _lib() -> Any:
    """The C library, loaded on the first call"""

    global _raw_argon2_lib
    with _raw_argon2_lock:
        if _raw_argon2_lib is None:
            # Imported here: it loads a C library, and importing KDF must not
            from Crypto.Util._cpu_features import load_avx2_bmi2_lib

            portable = load_pycryptodome_raw_lib("Crypto.Protocol._argon2_core", _ARGON2_CDECL)
            avx2_bmi2 = load_avx2_bmi2_lib("Crypto.Protocol._argon2_core_avx2_bmi2", _ARGON2_CDECL)
            _raw_argon2_libs["portable"] = portable
            if avx2_bmi2 is not None:
                _raw_argon2_libs["avx2_bmi2"] = avx2_bmi2
            _raw_argon2_lib = portable if avx2_bmi2 is None else avx2_bmi2
        return _raw_argon2_lib


class _Memory:
    """The C state of Argon2 (with the memory), shared by the caller and the
    threads it starts: it is wiped and freed by the last one that releases it.

    If the caller is interrupted (for instance by KeyboardInterrupt) while
    other threads are still filling it, the memory is freed only when
    those threads are done.
    """

    def __init__(self, lib: Any, state: Any, users: int) -> None:
        self._lib = lib
        self.state = state
        self._users = users
        self._lock = threading.Lock()

    def release(self) -> None:
        with self._lock:
            self._users -= 1
            last = self._users == 0
        if last:
            self._lib.argon2_destroy(self.state)


def _le32(x: int) -> bytes:
    return struct.pack("<I", x)


def _h_prime(data: bytes, tag_len: int) -> bytes:
    """The variable-length hash H' (RFC 9106, Section 3.3)"""

    data = _le32(tag_len) + data
    if tag_len <= 64:
        return BLAKE2b.new(digest_bytes=tag_len, data=data).digest()

    r = (tag_len + 31) // 32 - 2
    v = BLAKE2b.new(digest_bytes=64, data=data).digest()
    out = [v[:32]]
    for _ in range(r - 1):
        v = BLAKE2b.new(digest_bytes=64, data=v).digest()
        out.append(v[:32])
    out.append(BLAKE2b.new(digest_bytes=tag_len - 32 * r, data=v).digest())
    return b"".join(out)


def _check_int(name: str, value: Any, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("'%s' must be an integer" % name)
    if not low <= value <= high:
        raise ValueError("'%s' must be between %d and %d (it is %d)" % (name, low, high, value))
    return value


def _check_bytes(name: str, value: Any) -> bytes:
    if not is_buffer(value):
        raise TypeError("'%s' must be bytes, bytearray or memoryview" % name)
    value = bytes(value)
    if len(value) > _MAX_U32:
        raise ValueError("'%s' is too long" % name)
    return value


def _password_bytes(password: Union[str, Buffer]) -> bytes:
    if isinstance(password, str):
        password = password.encode("utf-8")
    return _check_bytes("password", password)


def _resolve(
    profile: Optional[Argon2Profile],
    time_cost: Optional[int],
    memory_cost: Optional[int],
    lanes: Optional[int],
    variant: Optional[Argon2Variant],
) -> tuple[Argon2Variant, int, int, int]:
    """Combine a profile and the explicit parameters (which override it),
    and check them against RFC 9106"""

    if profile is not None:
        if not isinstance(profile, Argon2Profile):
            raise TypeError("'profile' must be a member of Argon2Profile")
        if time_cost is None:
            time_cost = profile.time_cost
        if memory_cost is None:
            memory_cost = profile.memory_cost
        if lanes is None:
            lanes = profile.lanes
        if variant is None:
            variant = profile.variant
    else:
        missing = [
            name
            for name, value in (("time_cost", time_cost), ("memory_cost", memory_cost), ("lanes", lanes))
            if value is None
        ]
        if missing:
            raise TypeError(
                "Pass a profile, or all of time_cost, memory_cost and lanes (missing: %s)"
                % ", ".join(missing)
            )
        if variant is None:
            variant = Argon2Variant.ARGON2ID

    if not isinstance(variant, Argon2Variant):
        raise TypeError("'variant' must be a member of Argon2Variant")
    time_cost = _check_int("time_cost", time_cost, 1, _MAX_U32)
    lanes = _check_int("lanes", lanes, 1, _MAX_LANES)
    memory_cost = _check_int("memory_cost", memory_cost, 1, _MAX_U32)
    if memory_cost < 8 * lanes:
        raise ValueError("'memory_cost' must be at least 8 KiB for each lane (%d KiB)" % (8 * lanes))
    return variant, time_cost, memory_cost, lanes


def _blocks(memory_cost: int, lanes: int) -> int:
    """m', the actual number of 1 KiB blocks"""
    return 4 * lanes * (memory_cost // (4 * lanes))


def _argon2_raw(
    password: bytes,
    salt: bytes,
    tag_len: int,
    variant: Argon2Variant,
    time_cost: int,
    memory_cost: int,
    lanes: int,
    secret: bytes,
    associated_data: bytes,
    threads: int,
) -> bytes:
    """Argon2 (RFC 9106, Section 3.2), with parameters already checked"""

    y = _TYPE[variant]
    h0 = BLAKE2b.new(digest_bytes=64)
    for number in (lanes, tag_len, memory_cost, time_cost, _VERSION, y):
        h0.update(_le32(number))
    for field in (password, salt, secret, associated_data):
        h0.update(_le32(len(field)))
        h0.update(field)
    h0_digest = h0.digest()

    blocks = _blocks(memory_cost, lanes)
    lib = _lib()
    threads = max(1, min(threads_param(threads), lanes))

    state = VoidPointer()
    result = lib.argon2_new(state.address_of(), blocks, lanes, time_cost, y)
    if result == 2:  # ERR_MEMORY
        raise MemoryError("Cannot allocate %d bytes for Argon2" % (blocks * _BLOCK_SIZE))
    if result:
        raise ValueError("Error %d while initializing Argon2" % result)
    memory = _Memory(lib, state.get(), threads)

    try:
        st = memory.state
        for lane in range(lanes):
            for index in (0, 1):
                first = _h_prime(h0_digest + _le32(index) + _le32(lane), _BLOCK_SIZE)
                result = lib.argon2_set_block(st, lane, index, c_uint8_ptr(first))
                if result:
                    raise ValueError("Error %d while initializing Argon2" % result)

        def fill(lane_first: int, lane_end: int, pass_: int, slice_: int) -> None:
            for lane in range(lane_first, lane_end):
                result = lib.argon2_fill_segment(st, pass_, slice_, lane)
                if result:
                    raise ValueError("Error %d while running Argon2" % result)

        if threads == 1:
            for pass_ in range(time_cost):
                for slice_ in range(_SYNC_POINTS):
                    fill(0, lanes, pass_, slice_)
        else:
            # Each thread fills its own range of lanes, slice after slice:
            # all the threads wait for each other at the end of every slice
            bounds = range_boundaries(lanes, threads)
            barrier = threading.Barrier(threads)
            failures: list[BaseException] = []

            def worker(i: int) -> None:
                try:
                    for pass_ in range(time_cost):
                        for slice_ in range(_SYNC_POINTS):
                            fill(bounds[i], bounds[i + 1], pass_, slice_)
                            barrier.wait()
                except threading.BrokenBarrierError:
                    raise
                except BaseException as e:
                    failures.append(e)
                    barrier.abort()
                    raise
                finally:
                    # Thread 0 is the caller, which releases the memory below
                    if i:
                        memory.release()

            try:
                run_in_threads(worker, threads)
            except BaseException:
                barrier.abort()
                if failures:
                    raise failures[0] from None
                raise

        final = create_string_buffer(_BLOCK_SIZE)
        result = lib.argon2_get_final_block(st, final)
        if result:
            raise ValueError("Error %d while finishing Argon2" % result)
    finally:
        memory.release()

    return _h_prime(get_raw_buffer(final), tag_len)


@overload
def argon2(
    password: Union[str, Buffer],
    key_len: int,
    *,
    salt: Buffer,
    profile: Optional[Argon2Profile] = None,
    time_cost: Optional[int] = None,
    memory_cost: Optional[int] = None,
    lanes: Optional[int] = None,
    variant: Optional[Argon2Variant] = None,
    secret: Optional[Buffer] = None,
    associated_data: Optional[Buffer] = None,
    num_keys: Literal[1] = 1,
    threads: int = 1,
) -> bytes: ...


@overload
def argon2(
    password: Union[str, Buffer],
    key_len: int,
    *,
    salt: Buffer,
    profile: Optional[Argon2Profile] = None,
    time_cost: Optional[int] = None,
    memory_cost: Optional[int] = None,
    lanes: Optional[int] = None,
    variant: Optional[Argon2Variant] = None,
    secret: Optional[Buffer] = None,
    associated_data: Optional[Buffer] = None,
    num_keys: int,
    threads: int = 1,
) -> Union[bytes, list[bytes]]: ...


def argon2(
    password: Union[str, Buffer],
    key_len: int,
    *,
    salt: Buffer,
    profile: Optional[Argon2Profile] = None,
    time_cost: Optional[int] = None,
    memory_cost: Optional[int] = None,
    lanes: Optional[int] = None,
    variant: Optional[Argon2Variant] = None,
    secret: Optional[Buffer] = None,
    associated_data: Optional[Buffer] = None,
    num_keys: int = 1,
    threads: int = 1,
) -> Union[bytes, list[bytes]]:
    """Derive one or more keys from a password with Argon2 (`RFC 9106`_).

    The cost of the derivation comes from a ``profile``
    (a member of :class:`Argon2Profile`),
    or from ``time_cost``, ``memory_cost`` and ``lanes`` all together.
    With a profile, each explicit parameter overrides the same item of the profile.

    Args:
     password (string or bytes):
        The secret password or pass phrase.
        A string is encoded as UTF-8.
     key_len (integer):
        The length in bytes of each derived key.
     salt (bytes):
        A value that does not need to be secret, but that should be
        randomly chosen for each password: 16 bytes are recommended.
        It must be at least 8 bytes long.
        You need the same salt to derive the same key again.
     profile (:class:`Argon2Profile`):
        A published set of parameters, for instance
        ``Argon2Profile.RFC9106_2021_64MIB``.
     time_cost (integer):
        The number of passes over the memory (*t*), at least 1.
     memory_cost (integer):
        The memory to use, in **KiB** (*m*): at least 8 KiB for each lane,
        and at most :math:`2^{32}-1`.
        It is rounded down to a multiple of 4 KiB for each lane.
     lanes (integer):
        The degree of parallelism (*p*): the number of lanes the memory
        is divided into, from 1 to :math:`2^{24}-1`.
        It changes the result. It does not create threads (see ``threads``).
     variant (:class:`Argon2Variant`):
        The variant of Argon2. Without a profile, :attr:`Argon2Variant.ARGON2ID`.
     secret (bytes):
        An optional secret key (*K*), for instance a pepper kept apart from the salts.
     associated_data (bytes):
        Optional associated data (*X*), which is bound to the derived key.
     num_keys (integer):
        The number of keys to derive. Every key is ``key_len`` bytes long.
        By default, only 1 key is generated.
     threads (integer):
        The maximum number of threads that compute the lanes in parallel
        (default: 1, no extra threads; 0 for all CPU cores).
        At most ``lanes`` threads are used.
        The output does not depend on the number of threads.

    Return:
        A byte string, or a list of ``num_keys`` byte strings.

    Raises:
        TypeError: if a parameter has the wrong type, or if neither a profile
          nor all three costs are given
        ValueError: if a parameter is outside the range allowed by RFC 9106
        MemoryError: if the memory cannot be allocated

    .. _RFC 9106: https://www.rfc-editor.org/rfc/rfc9106
    """

    variant, time_cost, memory_cost, lanes = _resolve(profile, time_cost, memory_cost, lanes, variant)
    password_b = _password_bytes(password)
    salt_b = _check_bytes("salt", salt)
    if len(salt_b) < _MIN_SALT_LEN:
        raise ValueError("The salt must be at least %d bytes long" % _MIN_SALT_LEN)
    secret_b = _check_bytes("secret", b"" if secret is None else secret)
    ad_b = _check_bytes("associated_data", b"" if associated_data is None else associated_data)
    _check_int("key_len", key_len, 1, _MAX_U32)
    _check_int("num_keys", num_keys, 1, _MAX_U32)
    tag_len = key_len * num_keys
    if not _MIN_TAG_LEN <= tag_len <= _MAX_U32:
        raise ValueError(
            "The total length of the keys must be between %d and %d bytes" % (_MIN_TAG_LEN, _MAX_U32)
        )

    tag = _argon2_raw(
        password_b, salt_b, tag_len, variant, time_cost, memory_cost, lanes, secret_b, ad_b, threads
    )
    if num_keys == 1:
        return tag
    return [tag[i : i + key_len] for i in range(0, tag_len, key_len)]


def _b64encode(data: bytes) -> bytes:
    return binascii.b2a_base64(data, newline=False).rstrip(b"=")


def _b64decode(data: bytes) -> bytes:
    """Decode base64 without padding, as in PHC strings: the encoding must be canonical"""

    if len(data) % 4 == 1:
        raise ValueError("Incorrect base64 encoding in the Argon2 hash")
    try:
        result = binascii.a2b_base64(data + b"=" * (-len(data) % 4))
    except binascii.Error:
        raise ValueError("Incorrect base64 encoding in the Argon2 hash") from None
    if _b64encode(result) != data:
        raise ValueError("Non-canonical base64 encoding in the Argon2 hash")
    return result


def argon2_hash(
    password: Union[str, Buffer],
    *,
    profile: Optional[Argon2Profile] = None,
    time_cost: Optional[int] = None,
    memory_cost: Optional[int] = None,
    lanes: Optional[int] = None,
    variant: Optional[Argon2Variant] = None,
    salt: Optional[Buffer] = None,
    hash_len: Optional[int] = None,
    secret: Optional[Buffer] = None,
    threads: int = 1,
) -> bytes:
    """Hash a password with Argon2, for storage.

    The result is a PHC string, such as
    ``b'$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>'``, which contains the
    parameters and the salt: verify a password against it with :func:`argon2_check`.
    It is compatible with most other implementations of Argon2.

    Without a ``profile`` and without costs, the parameters are those of
    :data:`ARGON2_DEFAULT_PROFILE`, currently ``Argon2Profile.RFC9106_2021_64MIB``
    (Argon2id, 3 passes, 64 MiB, 4 lanes). Each explicit parameter overrides
    the same item of the profile (or of the default profile).

    Args:
      password (string or bytes):
        The secret password or pass phrase.
        A string is encoded as UTF-8.
      profile (:class:`Argon2Profile`):
        A published set of parameters.
      time_cost (integer):
        The number of passes over the memory (*t*).
      memory_cost (integer):
        The memory to use, in **KiB** (*m*).
      lanes (integer):
        The degree of parallelism (*p*).
      variant (:class:`Argon2Variant`):
        The variant of Argon2.
      salt (bytes):
        The salt, at least 8 bytes long. If not passed, a random salt is
        generated, as long as the profile recommends (16 bytes).
      hash_len (integer):
        The length of the hash in bytes, at least 4.
        If not passed, the length that the profile recommends (32 bytes).
      secret (bytes):
        An optional secret key (a pepper). It is not stored in the hash:
        :func:`argon2_check` needs it too.
      threads (integer):
        The maximum number of threads (default: 1; 0 for all CPU cores).
        It does not change the result.

    Return (bytes):
        The Argon2 hash, as a PHC string.
    """

    base = ARGON2_DEFAULT_PROFILE if profile is None else profile
    if not isinstance(base, Argon2Profile):
        raise TypeError("'profile' must be a member of Argon2Profile")
    if base.deprecated:
        warnings.warn(
            "The Argon2 profile %s is deprecated: %s" % (base.name, base.deprecated),
            DeprecationWarning,
            stacklevel=2,
        )
    variant, time_cost, memory_cost, lanes = _resolve(base, time_cost, memory_cost, lanes, variant)

    if salt is None:
        salt = get_random_bytes(base.salt_len)
    salt_b = _check_bytes("salt", salt)
    if len(salt_b) < _MIN_SALT_LEN:
        raise ValueError("The salt must be at least %d bytes long" % _MIN_SALT_LEN)
    if hash_len is None:
        hash_len = base.key_len
    hash_len = _check_int("hash_len", hash_len, _MIN_TAG_LEN, _MAX_U32)
    secret_b = _check_bytes("secret", b"" if secret is None else secret)

    tag = _argon2_raw(
        _password_bytes(password),
        salt_b,
        hash_len,
        variant,
        time_cost,
        memory_cost,
        lanes,
        secret_b,
        b"",
        threads,
    )
    params = b"m=%d,t=%d,p=%d" % (memory_cost, time_cost, lanes)
    return b"$".join(
        (b"", variant.value.encode("ascii"), b"v=19", params, _b64encode(salt_b), _b64encode(tag))
    )


# A decimal number without leading zeros
_DECIMAL = rb"(0|[1-9][0-9]*)"
_PHC_RE = re.compile(
    rb"\$([a-z0-9]+)\$v=([0-9]+)\$m="
    + _DECIMAL
    + rb",t="
    + _DECIMAL
    + rb",p="
    + _DECIMAL
    + rb"\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)"
)


def _check_limit(name: str, value: Optional[int]) -> None:
    if value is not None:
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("'%s' must be an integer or None" % name)
        if value < 0:
            raise ValueError("'%s' must be a non-negative integer" % name)


def argon2_check(
    password: Union[str, Buffer],
    argon2_hash: Union[bytes, bytearray, str],
    *,
    secret: Optional[Buffer] = None,
    max_memory: Optional[int] = None,
    max_cost: Optional[int] = None,
    threads: int = 1,
) -> None:
    """Verify a password against an Argon2 hash (a PHC string, as created
    by :func:`argon2_hash` or by most other implementations).

    The hash states its own parameters, so a hash from an untrusted source
    could need an enormous amount of memory or time. The derivation does not
    start if the hash exceeds ``max_memory`` or ``max_cost``.

    Args:
      password (string or bytes):
        The password to check.
        A string is encoded as UTF-8.
      argon2_hash (bytes or string):
        The reference hash, for instance ``$argon2id$v=19$m=65536,t=3,p=4$...``.
        Only version 19 (``v=19``) of Argon2 is supported.
      secret (bytes):
        The secret key (pepper) used to create the hash, if any.
      max_memory (integer):
        The maximum memory, in **bytes**, that the hash may need.
        The default value is None (256 MiB). Set it to ``0`` to disable the check.
        See :ref:`the limits for decryption<pkcs8_limits>`.
      max_cost (integer):
        The maximum number of passes times the memory (in KiB) of the hash.
        The default value is None (:math:`2^{25}`, about one minute on a recent laptop, with one thread).
        Set it to ``0`` to disable the check.
      threads (integer):
        The maximum number of threads (default: 1; 0 for all CPU cores).

    Raises:
        KdfMemoryLimitError: (a ``ValueError``) if the hash needs more memory than ``max_memory``
        KdfIterationLimitError: (a ``ValueError``) if the cost of the hash is above ``max_cost``
        ValueError: if the password does not match, or if the hash is not valid
    """

    from Crypto.IO._PBES import _DEFAULT_MAX_MEMORY

    _check_limit("max_memory", max_memory)
    _check_limit("max_cost", max_cost)

    encoded = tobytes(argon2_hash)
    match = _PHC_RE.fullmatch(encoded)
    if match is None:
        raise ValueError("Incorrect Argon2 hash format")
    identifier, version, m, t, p, salt64, tag64 = match.groups()

    try:
        variant = Argon2Variant(identifier.decode("ascii"))
    except ValueError:
        raise ValueError("Unsupported Argon2 variant: %r" % identifier) from None
    if version != b"19":
        raise ValueError("Unsupported Argon2 version: %r (only 19 is supported)" % version)
    if max(len(m), len(t), len(p)) > 10:
        raise ValueError("Incorrect Argon2 hash parameters")
    variant, time_cost, memory_cost, lanes = _resolve(None, int(t), int(m), int(p), variant)

    salt = _b64decode(salt64)
    tag = _b64decode(tag64)
    if len(salt) < _MIN_SALT_LEN:
        raise ValueError("The salt of the Argon2 hash is shorter than %d bytes" % _MIN_SALT_LEN)
    if len(tag) < _MIN_TAG_LEN:
        raise ValueError("The Argon2 hash is shorter than %d bytes" % _MIN_TAG_LEN)

    # Before any hashing: the costs come from the hash
    blocks = _blocks(memory_cost, lanes)
    memory = blocks * _BLOCK_SIZE
    if max_memory is None:
        limit = "%d (the default)" % _DEFAULT_MAX_MEMORY
        max_memory = _DEFAULT_MAX_MEMORY
    else:
        limit = str(max_memory)
    if max_memory and memory > max_memory:
        raise KdfMemoryLimitError(_MEMORY_ERROR.format(memory=memory, limit=limit))

    cost = time_cost * blocks
    if max_cost is None:
        limit = "%d (the default)" % _DEFAULT_MAX_ARGON2_COST
        max_cost = _DEFAULT_MAX_ARGON2_COST
    else:
        limit = str(max_cost)
    if max_cost and cost > max_cost:
        raise KdfIterationLimitError(_COST_ERROR.format(cost=cost, limit=limit))

    secret_b = _check_bytes("secret", b"" if secret is None else secret)
    computed = _argon2_raw(
        _password_bytes(password),
        salt,
        len(tag),
        variant,
        time_cost,
        memory_cost,
        lanes,
        secret_b,
        b"",
        threads,
    )
    if not compare_digest(computed, tag):
        raise ValueError("Incorrect Argon2 hash")
