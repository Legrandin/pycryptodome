/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * SLH-DSA (slhdsa.c), with SHA-256 using the Intel SHA extensions (SHA-NI).
 * It can only be loaded on a CPU that supports them.
 *
 * The exported functions have the same names as in slhdsa.c.
 */

#define SLHDSA_MODULE slhdsa_shani
#define SLHDSA_SHA_NI
#include "slhdsa.c"
