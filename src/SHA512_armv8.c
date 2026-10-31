/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * SHA-512 (SHA512.c), with the compression function using the
 * instructions of the ARMv8 Cryptography Extensions
 * (SHA512H, SHA512H2, SHA512SU0 and SHA512SU1, from ARMv8.2).
 * It can only be loaded on a CPU that supports them.
 *
 * The exported functions have the same names as in SHA512.c.
 */

#define SHA2_MODULE SHA512_armv8
#define SHA2_ARMV8
#include "SHA512.c"
