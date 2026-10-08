/*
 * SPDX-FileCopyrightText: 2026 Legrandin <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The Keccak sponge (keccak.c), compiled with AVX2, BMI1 and BMI2 enabled.
 * It can only be loaded on a CPU that supports all three.
 *
 * The code does not change: it gets faster just by compiling it with BMI1
 * (ANDN computes ~a & b in one instruction) and BMI2 (RORX rotates
 * without changing the flags, into a different register).
 * AVX2 is not used here, but it comes with the same compiler flags and
 * CPU check as k12_avx2_bmi2.c, which does use it.
 *
 * See KECCAK_K12.txt for which file includes which, and the resulting modules.
 */

#define KECCAK_MODULE keccak_avx2_bmi2
#include "keccak.c"
