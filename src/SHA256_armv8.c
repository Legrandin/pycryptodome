/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * SHA-256 (SHA256.c), with the compression function using the
 * instructions of the ARMv8 Cryptography Extensions
 * (SHA256H, SHA256H2, SHA256SU0 and SHA256SU1).
 * It can only be loaded on a CPU that supports them.
 *
 * The exported functions have the same names as in SHA256.c.
 */

#define SHA2_MODULE SHA256_armv8
#define SHA2_ARMV8
#include "SHA256.c"
