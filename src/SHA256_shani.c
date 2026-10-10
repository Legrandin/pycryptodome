/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * SHA-256 (SHA256.c), with the compression function using
 * the Intel SHA extensions (SHA-NI).
 * It can only be loaded on a CPU that supports them.
 *
 * The exported functions have the same names as in SHA256.c.
 */

#define SHA2_MODULE SHA256_shani
#define SHA2_SHA_NI
#include "SHA256.c"
