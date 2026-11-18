/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * SLH-DSA (slhdsa.c), with SHA-256 using the instructions of the ARMv8
 * Cryptography Extensions (SHA256H, SHA256H2, SHA256SU0 and SHA256SU1),
 * 4 hashes at once for the SHA2 parameter sets.
 * On 64-bit ARM, it can only be loaded on a CPU that supports them;
 * on other CPUs (the x86-64 half of a macOS universal2 build),
 * it is the portable code.
 *
 * The exported functions have the same names as in slhdsa.c.
 */

#define SLHDSA_MODULE slhdsa_armv8
#define SLHDSA_ARMV8
#include "slhdsa.c"
