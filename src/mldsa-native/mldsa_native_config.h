/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [FIPS140_3_IG]
 *   Implementation Guidance for FIPS 140-3 and the Cryptographic Module
 *   Validation Program
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-ig-announcements
 *
 * - [FIPS204]
 *   FIPS 204 Module-Lattice-Based Digital Signature Standard
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/pubs/fips/204/final
 *
 * - [FIPS204_UPDATES]
 *   FIPS 204 Potential Updates (Errata)
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/files/pubs/fips/204/final/docs/fips-204-potential-updates.xlsx
 */

#ifndef MLD_CONFIG_H
#define MLD_CONFIG_H

/**
 * MLD_CONFIG_PARAMETER_SET
 *
 * Specifies the parameter set for ML-DSA
 * - MLD_CONFIG_PARAMETER_SET=44 corresponds to ML-DSA-44
 * - MLD_CONFIG_PARAMETER_SET=65 corresponds to ML-DSA-65
 * - MLD_CONFIG_PARAMETER_SET=87 corresponds to ML-DSA-87
 *
 * If you want to support multiple parameter sets, build the
 * library multiple times and set MLD_CONFIG_MULTILEVEL_BUILD.
 * See MLD_CONFIG_MULTILEVEL_BUILD for how to do this while
 * minimizing code duplication.
 *
 * This can also be set using CFLAGS.
 */
#ifndef MLD_CONFIG_PARAMETER_SET
#define MLD_CONFIG_PARAMETER_SET \
  44 /* Change this for different security strengths */
#endif

/**
 * MLD_CONFIG_FILE
 *
 * If defined, this is a header that will be included instead
 * of the default configuration file mldsa/mldsa_native_config.h.
 *
 * When you need to build mldsa-native in multiple configurations,
 * using varying MLD_CONFIG_FILE can be more convenient
 * than configuring everything through CFLAGS.
 *
 * To use, MLD_CONFIG_FILE _must_ be defined prior
 * to the inclusion of any mldsa-native headers. For example,
 * it can be set by passing `-DMLD_CONFIG_FILE="..."`
 * on the command line.
 */
/* #define MLD_CONFIG_FILE "mldsa_native_config.h" */

/**
 * MLD_CONFIG_NAMESPACE_PREFIX
 *
 * The prefix to use to namespace global symbols from mldsa/.
 *
 * In a multi-level build, level-dependent symbols will
 * additionally be prefixed with the parameter set (44/65/87).
 *
 * This can also be set using CFLAGS.
 */
#if !defined(MLD_CONFIG_NAMESPACE_PREFIX)
#define MLD_CONFIG_NAMESPACE_PREFIX MLD_DEFAULT_NAMESPACE_PREFIX
#endif

/**
 * MLD_CONFIG_MULTILEVEL_BUILD
 *
 * Set this if the build is part of a multi-level build supporting
 * multiple parameter sets.
 *
 * If you need only a single parameter set, keep this unset.
 *
 * To build mldsa-native with support for all parameter sets,
 * build it three times -- once per parameter set -- and set the
 * option MLD_CONFIG_MULTILEVEL_WITH_SHARED for exactly one of
 * them, and MLD_CONFIG_MULTILEVEL_NO_SHARED for the others.
 * MLD_CONFIG_MULTILEVEL_BUILD should be set for all of them.
 *
 * See examples/multilevel_build for an example.
 *
 * This can also be set using CFLAGS.
 */
/* #define MLD_CONFIG_MULTILEVEL_BUILD */

/**
 * MLD_CONFIG_EXTERNAL_API_QUALIFIER
 *
 * If set, this option provides an additional function
 * qualifier to be added to declarations of mldsa-native's
 * public API.
 *
 * The primary use case for this option are single-CU builds
 * where the public API exposed by mldsa-native is wrapped by
 * another API in the consuming application. In this case,
 * even mldsa-native's public API can be marked `static`.
 */
/* #define MLD_CONFIG_EXTERNAL_API_QUALIFIER */

/**
 * MLD_CONFIG_NO_KEYPAIR_API
 *
 * By default, mldsa-native includes support for generating key
 * pairs. If you don't need this, set MLD_CONFIG_NO_KEYPAIR_API
 * to exclude keypair, keypair_internal,
 * pk_from_sk, and all internal APIs only needed by
 * those functions.
 */
/* #define MLD_CONFIG_NO_KEYPAIR_API */

/**
 * MLD_CONFIG_NO_SIGN_API
 *
 * By default, mldsa-native includes support for creating
 * signatures. If you don't need this, set MLD_CONFIG_NO_SIGN_API
 * to exclude signature,
 * signature_extmu, signature_internal,
 * signature_pre_hash_internal,
 * signature_pre_hash_shake256, and all internal APIs
 * only needed by those functions.
 */
/* #define MLD_CONFIG_NO_SIGN_API */

/**
 * MLD_CONFIG_NO_VERIFY_API
 *
 * By default, mldsa-native includes support for verifying
 * signatures. If you don't need this, set
 * MLD_CONFIG_NO_VERIFY_API to exclude verify,
 * verify_extmu, verify_internal,
 * verify_pre_hash_internal,
 * verify_pre_hash_shake256, and all internal APIs
 * only needed by those functions.
 */
/* #define MLD_CONFIG_NO_VERIFY_API */

/**
 * MLD_CONFIG_CORE_API_ONLY
 *
 * Set this to remove all public APIs except
 * keypair_internal, signature_internal,
 * and verify_internal.
 */
/* #define MLD_CONFIG_CORE_API_ONLY */

/**
 * MLD_CONFIG_NO_RANDOMIZED_API
 *
 * If this option is set, mldsa-native will be built without the
 * randomized API functions (keypair,
 * signature, and signature_extmu).
 * This allows users to build mldsa-native without providing a
 * randombytes() implementation if they only need the
 * internal deterministic API
 * (keypair_internal, signature_internal).
 *
 * @note This option is incompatible with MLD_CONFIG_KEYGEN_PCT
 * as the current PCT implementation requires
 * signature().
 */
/* #define MLD_CONFIG_NO_RANDOMIZED_API */

/**
 * MLD_CONFIG_CONSTANTS_ONLY
 *
 * If you only need the size constants (MLDSA_PUBLICKEYBYTES, etc.)
 * but no function declarations, set MLD_CONFIG_CONSTANTS_ONLY.
 *
 * This only affects the public header mldsa_native.h, not
 * the implementation.
 */
/* #define MLD_CONFIG_CONSTANTS_ONLY */
/******************************************************************************
 *
 * Build-only configuration options
 *
 * The remaining configurations are build-options only.
 * They do not affect the API described in mldsa_native.h.
 *
 *****************************************************************************/
#if defined(MLD_BUILD_INTERNAL)

/**
 * MLD_CONFIG_MULTILEVEL_WITH_SHARED
 *
 * This is for multi-level builds of mldsa-native only. If you
 * need only a single parameter set, keep this unset.
 *
 * If this is set, all MLD_CONFIG_PARAMETER_SET-independent
 * code will be included in the build, including code needed only
 * for other parameter sets.
 *
 * Example: mld_polyw1_pack_88 is only needed for
 * MLD_CONFIG_PARAMETER_SET == 44. Yet, if this option is set for a
 * build with MLD_CONFIG_PARAMETER_SET == 65/87, it would be included.
 *
 * To build mldsa-native with support for all parameter sets,
 * build it three times -- once per parameter set -- and set the
 * option MLD_CONFIG_MULTILEVEL_WITH_SHARED for exactly one of
 * them, and MLD_CONFIG_MULTILEVEL_NO_SHARED for the others.
 * MLD_CONFIG_MULTILEVEL_BUILD should be set for all of them.
 *
 * See examples/multilevel_build for an example.
 *
 * This can also be set using CFLAGS.
 */
/* #define MLD_CONFIG_MULTILEVEL_WITH_SHARED */

/**
 * MLD_CONFIG_MULTILEVEL_NO_SHARED
 *
 * This is for multi-level builds of mldsa-native only. If you
 * need only a single parameter set, keep this unset.
 *
 * If this is set, no MLD_CONFIG_PARAMETER_SET-independent code
 * will be included in the build.
 *
 * To build mldsa-native with support for all parameter sets,
 * build it three times -- once per parameter set -- and set the
 * option MLD_CONFIG_MULTILEVEL_WITH_SHARED for exactly one of
 * them, and MLD_CONFIG_MULTILEVEL_NO_SHARED for the others.
 * MLD_CONFIG_MULTILEVEL_BUILD should be set for all of them.
 *
 * See examples/multilevel_build for an example.
 *
 * This can also be set using CFLAGS.
 */
/* #define MLD_CONFIG_MULTILEVEL_NO_SHARED */

/**
 * MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
 *
 * This is only relevant for single compilation unit (SCU)
 * builds of mldsa-native. In this case, it determines whether
 * directives defined in parameter-set-independent headers should
 * be #undef'ined or not at the end of the SCU file. This is
 * needed in multilevel builds.
 *
 * See examples/multilevel_build_native for an example.
 *
 * This can also be set using CFLAGS.
 */
/* #define MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS */

/**
 * MLD_CONFIG_USE_NATIVE_BACKEND_ARITH
 *
 * Determines whether a native arithmetic backend should be used.
 *
 * The arithmetic backend covers performance-critical functions
 * such as the number-theoretic transform (NTT).
 *
 * If this option is unset, the C backend will be used.
 *
 * If this option is set, the arithmetic backend to be used is
 * determined by MLD_CONFIG_ARITH_BACKEND_FILE: If the latter is
 * unset, the default backend for your target architecture
 * will be used. If set, it must be the name of a backend metadata
 * file.
 *
 * This can also be set using CFLAGS.
 */
#if !defined(MLD_CONFIG_USE_NATIVE_BACKEND_ARITH)
/* #define MLD_CONFIG_USE_NATIVE_BACKEND_ARITH */
#endif

/**
 * MLD_CONFIG_ARITH_BACKEND_FILE
 *
 * The arithmetic backend to use.
 *
 * If MLD_CONFIG_USE_NATIVE_BACKEND_ARITH is unset, this option
 * is ignored.
 *
 * If MLD_CONFIG_USE_NATIVE_BACKEND_ARITH is set, this option must
 * either be undefined or the filename of an arithmetic backend.
 * If unset, the default backend will be used.
 *
 * This can be set using CFLAGS.
 */
#if defined(MLD_CONFIG_USE_NATIVE_BACKEND_ARITH) && \
    !defined(MLD_CONFIG_ARITH_BACKEND_FILE)
#define MLD_CONFIG_ARITH_BACKEND_FILE "native/meta.h"
#endif

/**
 * MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202
 *
 * Determines whether a native FIPS202 backend should be used.
 *
 * The FIPS202 backend covers 1x/2x/4x-fold Keccak-f1600, which is
 * the performance bottleneck of SHA3 and SHAKE.
 *
 * If this option is unset, the C backend will be used.
 *
 * If this option is set, the FIPS202 backend to be used is
 * determined by MLD_CONFIG_FIPS202_BACKEND_FILE: If the latter is
 * unset, the default backend for your target architecture
 * will be used. If set, it must be the name of a backend metadata
 * file.
 *
 * This can also be set using CFLAGS.
 */
#if !defined(MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202)
/* #define MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202 */
#endif

/**
 * MLD_CONFIG_FIPS202_BACKEND_FILE
 *
 * The FIPS-202 backend to use.
 *
 * If MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202 is set, this option
 * must either be undefined or the filename of a FIPS202 backend.
 * If unset, the default backend will be used.
 *
 * This can be set using CFLAGS.
 */
#if defined(MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202) && \
    !defined(MLD_CONFIG_FIPS202_BACKEND_FILE)
#define MLD_CONFIG_FIPS202_BACKEND_FILE "fips202/native/auto.h"
#endif

/**
 * MLD_CONFIG_FIPS202_CUSTOM_HEADER
 *
 * Custom header to use for FIPS-202
 *
 * This should only be set if you intend to use a custom
 * FIPS-202 implementation, different from the one shipped
 * with mldsa-native.
 *
 * If set, it must be the name of a file serving as the
 * replacement for mldsa/src/fips202/fips202.h, and exposing
 * the same API (see FIPS202.md).
 */
/* #define MLD_CONFIG_FIPS202_CUSTOM_HEADER "SOME_FILE.h" */

/**
 * MLD_CONFIG_FIPS202X4_CUSTOM_HEADER
 *
 * Custom header to use for FIPS-202-X4
 *
 * This should only be set if you intend to use a custom
 * FIPS-202 implementation, different from the one shipped
 * with mldsa-native.
 *
 * If set, it must be the name of a file serving as the
 * replacement for mldsa/src/fips202/fips202x4.h, and exposing
 * the same API (see FIPS202.md).
 */
/* #define MLD_CONFIG_FIPS202X4_CUSTOM_HEADER "SOME_FILE.h" */

/**
 * MLD_CONFIG_CUSTOM_ZEROIZE
 *
 * In compliance with @[FIPS204, Section 3.6.3], mldsa-native zeroizes
 * intermediate buffers before returning from function calls. By default,
 * those buffers are allocated from the stack; if MLD_CONFIG_CUSTOM_ALLOC_FREE
 * is set, they are (mostly -- few exceptions remain at present) allocated from
 * the configured custom allocator.
 *
 * mldsa-native also zeroizes caller-owned output buffers as needed to uphold
 * the API convention that outputs be either unmodified or zeroized upon
 * failure.
 *
 * Set this option and define `mld_zeroize` if you want to use a custom
 * method to zeroize intermediate and output buffers.
 *
 * The default implementation uses SecureZeroMemory on Windows and a
 * memset + compiler barrier otherwise. If neither of those is available on
 * the target platform, compilation will fail, and you will need to use
 * MLD_CONFIG_CUSTOM_ZEROIZE to provide a custom implementation of
 * `mld_zeroize()`.
 *
 * @warning
 *   The zeroization conducted by mldsa-native reduces the likelihood of data
 *   leaking on the stack or custom allocators, but it does not eliminate it.
 *   For example, the C standard makes no guarantee about where a compiler
 *   allocates local structures and whether/where it makes copies of them.
 *   Also, in addition to entire structures, there may also be potentially
 *   exploitable leakage of individual values on the stack. If you need
 *   bullet-proof zeroization of the stack, you need to consider additional
 *   measures instead of what this feature provides. In this case, you can
 *   set mld_zeroize to a no-op. Note that in this case you are also responsible
 *   for zeroizing output buffers upon failure.
 */
/* #define MLD_CONFIG_CUSTOM_ZEROIZE
   #if !defined(__ASSEMBLER__)
   #include <stdint.h>
   #include "src/src.h"
   static MLD_INLINE void mld_zeroize(void *ptr, size_t len)
   {
       ... your implementation ...
   }
   #endif
*/

/**
 * MLD_CONFIG_CUSTOM_RANDOMBYTES
 *
 * mldsa-native does not provide a secure randombytes
 * implementation. Such an implementation has to be provided by
 * the consumer.
 *
 * If this option is not set, mldsa-native expects a function
 * int randombytes(uint8_t *out, size_t outlen).
 *
 * Set this option and define `mld_randombytes` if you want to
 * use a custom method to sample randombytes with a different name
 * or signature.
 */
/* #define MLD_CONFIG_CUSTOM_RANDOMBYTES
   #if !defined(__ASSEMBLER__)
   #include <stdint.h>
   #include "src/src.h"
   static MLD_INLINE int mld_randombytes(uint8_t *ptr, size_t len)
   {
       ... your implementation ...
       return 0;
   }
   #endif
*/

/**
 * MLD_CONFIG_CUSTOM_CAPABILITY_FUNC
 *
 * mldsa-native backends may rely on specific hardware features.
 * Those backends will only be included in an mldsa-native build
 * if support for the respective features is enabled at
 * compile-time. However, when building for a heterogeneous set
 * of CPUs to run the resulting binary/library on, feature
 * detection at _runtime_ is needed to decide whether a backend
 * can be used or not.
 *
 * Set this option and define `mld_sys_check_capability` if you
 * want to use a custom method to dispatch between implementations.
 *
 * Return value 1 indicates that a capability is supported.
 * Return value 0 indicates that a capability is not supported.
 *
 * If this option is not set, mldsa-native uses compile-time
 * feature detection only to decide which backend to use.
 *
 * If you compile mldsa-native on a system with different
 * capabilities than the system that the resulting binary/library
 * will be run on, you must use this option.
 */
/* #define MLD_CONFIG_CUSTOM_CAPABILITY_FUNC
   static MLD_INLINE int mld_sys_check_capability(mld_sys_cap cap)
   {
       ... your implementation ...
   }
*/

/**
 * MLD_CONFIG_CUSTOM_ALLOC_FREE
 *
 * Set this option and define `MLD_CUSTOM_ALLOC` and
 * `MLD_CUSTOM_FREE` if you want to use custom allocation for
 * large local structures or buffers.
 *
 * By default, all buffers/structures are allocated on the stack.
 * If this option is set, most of them will be allocated via
 * MLD_CUSTOM_ALLOC.
 *
 * Parameters to MLD_CUSTOM_ALLOC:
 * - T* v: Target pointer to declare.
 * - T: Type of structure to be allocated
 * - N: Number of elements to be allocated.
 *
 * Parameters to MLD_CUSTOM_FREE:
 * - T* v: Target pointer to free. May be NULL.
 * - T: Type of structure to be freed.
 * - N: Number of elements to be freed.
 *
 * @warning This option is experimental. Its scope, configuration and
 *          function/macro signatures may change at any time. We expect a
 *          stable API in a future version.
 *
 * @note Even if this option is set, some allocations further down
 * the call stack will still be made from the stack. Those will
 * likely be added to the scope of this option in the future.
 *
 * @note MLD_CUSTOM_ALLOC need not guarantee a successful
 * allocation nor include error handling. Upon failure, the
 * target pointer should simply be set to NULL. The calling
 * code will handle this case and invoke MLD_CUSTOM_FREE.
 */
/* #define MLD_CONFIG_CUSTOM_ALLOC_FREE
   #if !defined(__ASSEMBLER__)
   #include <stdlib.h>
   #define MLD_CUSTOM_ALLOC(v, T, N)                              \
     T* (v) = (T *)aligned_alloc(MLD_DEFAULT_ALIGN,               \
                                 MLD_ALIGN_UP(sizeof(T) * (N)))
   #define MLD_CUSTOM_FREE(v, T, N) free(v)
   #endif
*/

/**
 * MLD_CONFIG_CUSTOM_MEMCPY
 *
 * Set this option and define `mld_memcpy` if you want to
 * use a custom method to copy memory instead of the standard
 * library memcpy function.
 *
 * The custom implementation must have the same signature and
 * behavior as the standard memcpy function:
 * void *mld_memcpy(void *dest, const void *src, size_t n)
 */
/* #define MLD_CONFIG_CUSTOM_MEMCPY
   #if !defined(__ASSEMBLER__)
   #include <stdint.h>
   #include "src/src.h"
   static MLD_INLINE void *mld_memcpy(void *dest, const void *src, size_t n)
   {
       ... your implementation ...
   }
   #endif
*/

/**
 * MLD_CONFIG_CUSTOM_MEMSET
 *
 * Set this option and define `mld_memset` if you want to
 * use a custom method to set memory instead of the standard
 * library memset function.
 *
 * The custom implementation must have the same signature and
 * behavior as the standard memset function:
 * void *mld_memset(void *s, int c, size_t n)
 */
/* #define MLD_CONFIG_CUSTOM_MEMSET
   #if !defined(__ASSEMBLER__)
   #include <stdint.h>
   #include "src/src.h"
   static MLD_INLINE void *mld_memset(void *s, int c, size_t n)
   {
       ... your implementation ...
   }
   #endif
*/

/**
 * MLD_CONFIG_INTERNAL_API_QUALIFIER
 *
 * If set, this option provides an additional qualifier
 * to be added to declarations of internal API functions and data.
 *
 * The primary use case for this option are single-CU builds,
 * in which case this option can be set to `static`.
 */
/* #define MLD_CONFIG_INTERNAL_API_QUALIFIER */

/**
 * MLD_CONFIG_CT_TESTING_ENABLED
 *
 * If set, mldsa-native annotates data as secret / public using
 * valgrind's annotations VALGRIND_MAKE_MEM_UNDEFINED and
 * VALGRIND_MAKE_MEM_DEFINED, enabling various checks for secret-
 * dependent control flow of variable time execution (depending
 * on the exact version of valgrind installed).
 */
/* #define MLD_CONFIG_CT_TESTING_ENABLED */

/**
 * MLD_CONFIG_NO_ASM
 *
 * If this option is set, mldsa-native will be built without
 * use of native code or inline assembly.
 *
 * By default, inline assembly is used to implement value barriers.
 * Without inline assembly, mldsa-native will use a global volatile
 * 'opt blocker' instead; see ct.h.
 *
 * Inline assembly is also used to implement a secure zeroization
 * function on non-Windows platforms. If this option is set and
 * the target platform is not Windows, you MUST set
 * MLD_CONFIG_CUSTOM_ZEROIZE and provide a custom zeroization
 * function.
 *
 * If this option is set, MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202 and
 * MLD_CONFIG_USE_NATIVE_BACKEND_ARITH will be ignored, and no
 * native backends will be used.
 */
/* #define MLD_CONFIG_NO_ASM */

/**
 * MLD_CONFIG_NO_ASM_VALUE_BARRIER
 *
 * If this option is set, mldsa-native will be built without
 * use of native code or inline assembly for value barriers.
 *
 * By default, inline assembly (if available) is used to implement
 * value barriers.
 * Without inline assembly, mldsa-native will use a global volatile
 * 'opt blocker' instead; see ct.h.
 */
/* #define MLD_CONFIG_NO_ASM_VALUE_BARRIER */

/**
 * MLD_CONFIG_KEYGEN_PCT
 *
 * Compliance with @[FIPS140_3_IG, p.87] requires a
 * Pairwise Consistency Test (PCT) to be carried out on a freshly
 * generated keypair before it can be exported.
 *
 * Set this option if such a check should be implemented.
 * In this case, keypair_internal and
 * keypair will return MLD_ERR_PCT_FAIL if the
 * PCT failed.
 *
 * @note This feature will drastically lower the performance of
 * key generation.
 *
 * @note This option is incompatible with MLD_CONFIG_NO_SIGN_API
 * and MLD_CONFIG_NO_VERIFY_API as the current PCT implementation
 * requires signature() and verify().
 */
/* #define MLD_CONFIG_KEYGEN_PCT */

/**
 * MLD_CONFIG_KEYGEN_PCT_BREAKAGE_TEST
 *
 * If this option is set, the user must provide a runtime
 * function `static inline int mld_break_pct() { ... }` to
 * indicate whether the PCT should be made fail.
 *
 * This option only has an effect if MLD_CONFIG_KEYGEN_PCT is set.
 */
/* #define MLD_CONFIG_KEYGEN_PCT_BREAKAGE_TEST
   #if !defined(__ASSEMBLER__)
   #include "src/src.h"
   static MLD_INLINE int mld_break_pct(void)
   {
       ... return 0/1 depending on whether PCT should be broken ...
   }
   #endif
*/

/**
 * MLD_CONFIG_MAX_SIGNING_ATTEMPTS
 *
 * Upper bound on the number of rejection-sampling iterations
 * performed by ML-DSA signing (@[FIPS204, Algorithm 7]).
 *
 * If a valid signature is not produced within this many
 * attempts, signing returns MLD_ERR_SIGN_ATTEMPTS_EXHAUSTED.
 * This is useful in timing-sensitive environments that
 * require a deterministic worst-case bound on signing time.
 *
 * For FIPS 204 compliance, this value MUST be at least 821,
 * cf. @[FIPS204, Appendix C] and @[FIPS204_UPDATES], which is
 * chosen so that the signing failure rate is < 2^{-256}.
 *
 * Default: Largest possible value before internal counters
 * would overflow. This is larger than the FIPS204 bound.
 *
 * In particular, in the default configuration, the signing
 * failure rate is < 2^{-256}.
 */
/* #define MLD_CONFIG_MAX_SIGNING_ATTEMPTS 821 */

/**
 * MLD_CONFIG_SERIAL_FIPS202_ONLY
 *
 * Set this to use a FIPS202 implementation with global state
 * that supports only one active Keccak computation at a time
 * (e.g. some hardware accelerators).
 *
 * If this option is set, ML-DSA will use FIPS202 operations
 * serially, ensuring that only one SHAKE context is active
 * at any given time.
 *
 * This allows offloading Keccak computations to a hardware
 * accelerator that holds only a single Keccak state locally,
 * rather than requiring support for multiple concurrent
 * Keccak states.
 *
 * @note Depending on the target CPU, this may reduce
 * performance when using software FIPS202 implementations.
 * Only enable this when you have to.
 */
/* #define MLD_CONFIG_SERIAL_FIPS202_ONLY */

/**
 * MLD_CONFIG_CONTEXT_PARAMETER
 *
 * Set this to add a caller-supplied context parameter to the public API
 * functions, which is then forwarded unchanged to the custom callbacks
 * (allocation, and signing hooks below).
 *
 * When this option is set, every public API function gains a trailing
 * parameter
 *
 *   MLD_CONFIG_CONTEXT_PARAMETER_TYPE context
 *
 * as its last argument; its type is configured via
 * MLD_CONFIG_CONTEXT_PARAMETER_TYPE (see below). mldsa-native treats this
 * value as opaque: it never dereferences it and only passes it on to the
 * configurable hook macros. It is meant to carry per-caller state -- e.g. a
 * pointer to a memory pool for the allocation hooks, or the resume state for
 * the signing hooks -- into those hooks.
 *
 * When this option is unset (the default), no extra parameter is added and
 * the hook macros never receive a context argument.
 *
 * The hooks that receive the context are the allocation hooks (see
 * MLD_CONFIG_CUSTOM_ALLOC_FREE) and the signing hooks (see
 * MLD_CONFIG_SIGN_HOOK_RESUME / _ATTEMPT / _FINISH); each is documented with
 * its own option below.
 */
/* #define MLD_CONFIG_CONTEXT_PARAMETER */

/**
 * MLD_CONFIG_CONTEXT_PARAMETER_TYPE
 *
 * Set this to define the type of the context parameter added by
 * MLD_CONFIG_CONTEXT_PARAMETER. It can be any C type usable as a function
 * parameter, e.g. `void *` or a pointer to a caller-defined struct such as
 * `struct my_ctx *`.
 *
 * This option must be defined if and only if MLD_CONFIG_CONTEXT_PARAMETER is
 * defined; defining one without the other is a compile-time error.
 */
/* #define MLD_CONFIG_CONTEXT_PARAMETER_TYPE void* */

/**
 * Signing hooks: MLD_CONFIG_SIGN_HOOK_RESUME / _ATTEMPT / _FINISH
 *
 * Three optional, independent hooks into the ML-DSA signing rejection-sampling
 * loop. Each is enabled by defining the matching option, in which case the
 * integration must provide the corresponding function. If a hook needs
 * per-operation state, enable MLD_CONFIG_CONTEXT_PARAMETER; the context is then
 * appended as the last argument.
 *
 * @warning This feature is experimental. Its scope, configuration and
 *          function signatures may change at any time, including after v2.
 *
 * Enabling any of the hooks requires MLD_CONFIG_NO_RANDOMIZED_API (restricting
 * the public API to deterministic operations). This is because the restartable
 * signing as enabled by the signing hooks only produces the uninterrupted
 * signature when the randomness is fixed across calls. A logging-only use
 * (attempt always returns 0; resume/finish merely observe) would be safe with
 * the randomized API too, but for now the requirement is imposed uniformly on
 * all three hooks.
 *
 * Note: Randomized signing is a shim wrapper around deterministic signing, and
 * all helper functions you need to build it are exposed publicly. Thus, if you
 * need a restartable, randomized signing operation, you can build your own by
 * replicating the logic and adding the RNG seed to the restart context. In this
 * case, please also consider letting the mldsa-native maintainers know of your
 * need for randomized, restartable signing, so the feature can be appropriately
 * prioritized.
 *
 * - MLD_CONFIG_SIGN_HOOK_ATTEMPT: int mld_sign_hook_attempt(attempt[, ctxt])
 *   Called before each attempt. Returns 0 to proceed, or non-zero to pause:
 *   signing then returns MLD_ERR_SIGNING_PAUSED with `attempt` as the resume
 *   point (needs MLD_CONFIG_SIGN_HOOK_RESUME to resume; otherwise just aborts).
 *   Always returning 0 makes it a logging/benchmarking hook.
 *
 * - MLD_CONFIG_SIGN_HOOK_RESUME: uint16_t mld_sign_hook_resume([ctxt])
 *   Returns the attempt to resume from (0 for a fresh operation), i.e. the one
 *   recorded when a previous call paused.
 *
 * - MLD_CONFIG_SIGN_HOOK_FINISH: void mld_sign_hook_finish(attempt[, ctxt])
 *   Called on success with the succeeding attempt. Observe-only.
 *
 * When an option is unset, the hook is a no-op (resume to 0, attempt proceeds),
 * i.e. ordinary one-shot signing.
 *
 * Independent of MLD_CONFIG_MAX_SIGNING_ATTEMPTS, which is a static upper bound
 * on the number of signing attempts.
 *
 * See test/src/test_sign_hook.c for a worked example using all three.
 */
/* #define MLD_CONFIG_SIGN_HOOK_RESUME
   #define MLD_CONFIG_SIGN_HOOK_ATTEMPT
   #define MLD_CONFIG_SIGN_HOOK_FINISH
   #if !defined(__ASSEMBLER__)
   #include <stdint.h>
   #include "src/sys.h"
   static MLD_INLINE uint16_t mld_sign_hook_resume(void)
   {
       ... return the attempt to resume from ...
   }
   static MLD_INLINE int mld_sign_hook_attempt(uint16_t attempt)
   {
       ... return non-zero to pause here; for resume, store attempt ...
       return 0;
   }
   static MLD_INLINE void mld_sign_hook_finish(uint16_t attempt)
   {
       ... mark the operation complete (attempt = successful attempt) ...
   }
   #endif
*/

/**
 * MLD_CONFIG_REDUCE_RAM
 *
 * Set this to reduce RAM usage. This trades memory for performance.
 *
 * For expected memory usage, see the MLD_TOTAL_ALLOC_* constants defined in
 * mldsa_native.h.
 *
 * This option is useful for embedded systems with tight RAM constraints but
 * relaxed performance requirements.
 *
 */
/* #define MLD_CONFIG_REDUCE_RAM */

/*************************  Config internals  ********************************/

#endif /* MLD_BUILD_INTERNAL */

/* Default namespace
 *
 * Don't change this. If you need a different namespace, re-define
 * MLD_CONFIG_NAMESPACE_PREFIX above instead, and remove the following.
 *
 * The default MLDSA namespace is
 *
 *   PQCP_MLDSA_NATIVE_MLDSA<LEVEL>_
 *
 * e.g., PQCP_MLDSA_NATIVE_MLDSA44_
 */

#if defined(MLD_CONFIG_MULTILEVEL_BUILD)
/* In a multi-level build the parameter set is appended by the namespacing
 * machinery, so the default prefix must not embed it. */
#define MLD_DEFAULT_NAMESPACE_PREFIX PQCP_MLDSA_NATIVE_MLDSA
#elif MLD_CONFIG_PARAMETER_SET == 44
#define MLD_DEFAULT_NAMESPACE_PREFIX PQCP_MLDSA_NATIVE_MLDSA44
#elif MLD_CONFIG_PARAMETER_SET == 65
#define MLD_DEFAULT_NAMESPACE_PREFIX PQCP_MLDSA_NATIVE_MLDSA65
#elif MLD_CONFIG_PARAMETER_SET == 87
#define MLD_DEFAULT_NAMESPACE_PREFIX PQCP_MLDSA_NATIVE_MLDSA87
#endif

#endif /* !MLD_CONFIG_H */
