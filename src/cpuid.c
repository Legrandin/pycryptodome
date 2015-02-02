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

#include "pycrypto_common.h"

FAKE_INIT(cpuid)

#if defined HAVE_CPUID_H
#include <cpuid.h>
#elif defined HAVE_INTRIN_H
#include <intrin.h>
#endif

/** Return 1 if the CPU supports the AESNI extension **/
EXPORT_SYM int have_aes_ni(void)
{
    uint32_t info[4];

    memset(info, 0, sizeof info);
    
    /* Call cpuid to retrieve x86 Processor Info and Feature bits.
     * info[2] is ecx. If bit 25 is set, the CPU supports the
     * AES-NI extension. */
#if defined HAVE_CPUID_H
    __get_cpuid(1, info, info+1, info+2, info+3);
#elif defined HAVE_INTRIN_H
    __cpuidex(info, 1, 0);
#endif

    return (info[2] & ((int)1<<25)) ? 1 : 0;
}
