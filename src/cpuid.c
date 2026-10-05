/* ===================================================================
 *
 * Copyright (c) 2014, Legrandin <helderijs@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * ===================================================================
 */

#include "common.h"

FAKE_INIT(cpuid_c)

#if defined HAVE_CPUID_H
#include <cpuid.h>
#include <immintrin.h>
#elif defined HAVE_INTRIN_H
#include <intrin.h>
#endif

/** Call X86 CPUID for Leaf 1: return CX **/
static uint32_t leaf1_ecx(void)
{
    uint32_t info[4];

    memset(info, 0, sizeof info);
 #if defined(HAVE_CPUID_H)
    __get_cpuid(1, info, info+1, info+2, info+3);
#elif defined(HAVE_INTRIN_H)
    __cpuidex(info, 1, 0);
#endif

    return info[2];
}


/** Return 1 if the CPU supports the AESNI extension **/
EXPORT_SYM int have_aes_ni(void)
{
    uint32_t ecx;

    ecx = leaf1_ecx();
    return (ecx & (1UL<<25)) ? 1 : 0;
}

/** Return non-zero if the CPU supports the PCLMULQDQ instruction (carry-less
 * multiplication). **/
EXPORT_SYM int have_clmul(void)
{
    uint32_t ecx;

    ecx = leaf1_ecx();
    return (ecx >> 1) & 1;
}

#if defined(HAVE_CPUID_H)

/** Call X86 CPUID for Leaf 7, Subleaf 0: return BX (0 if the leaf is not available) **/
static uint32_t leaf7_ebx(void)
{
    uint32_t eax, ebx, ecx, edx;

    if (__get_cpuid_max(0, NULL) < 7)
        return 0;
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return ebx;
}

/** Read the XCR0 register, which tells which registers the OS saves on
 * a context switch. The XGETBV instruction is only valid if CPUID reports
 * OSXSAVE. **/
__attribute__((target("xsave")))
static uint64_t read_xcr0(void)
{
    return _xgetbv(0);
}

/** Return non-zero if the CPU supports AVX2 and the OS saves the 256-bit
 * YMM registers. **/
EXPORT_SYM int have_avx2(void)
{
    uint32_t ecx;
    const uint32_t xcr0_sse_avx = (1U<<1) | (1U<<2);

    /* Leaf 1: OSXSAVE (bit 27) and AVX (bit 28) */
    ecx = leaf1_ecx();
    if ((ecx & (1UL<<27)) == 0 || (ecx & (1UL<<28)) == 0)
        return 0;

    /* The OS must save both the XMM and the YMM registers */
    if ((read_xcr0() & xcr0_sse_avx) != xcr0_sse_avx)
        return 0;

    /* Leaf 7: AVX2 (EBX bit 5) */
    return (leaf7_ebx() >> 5) & 1;
}

/** Return non-zero if the CPU supports BMI1 (ANDN and other bit
 * manipulation instructions). **/
EXPORT_SYM int have_bmi1(void)
{
    return (leaf7_ebx() >> 3) & 1;
}

/** Return non-zero if the CPU supports BMI2 (RORX and other bit
 * manipulation instructions). **/
EXPORT_SYM int have_bmi2(void)
{
    return (leaf7_ebx() >> 8) & 1;
}

#else

/** AVX2, BMI1 and BMI2 are only detected with gcc and clang for now **/

EXPORT_SYM int have_avx2(void)
{
    return 0;
}

EXPORT_SYM int have_bmi1(void)
{
    return 0;
}

EXPORT_SYM int have_bmi2(void)
{
    return 0;
}

#endif
