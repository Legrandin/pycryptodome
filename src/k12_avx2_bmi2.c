/*
 * SPDX-FileCopyrightText: 2026 Legrandin <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * KangarooTwelve (k12.c), compiled with AVX2, BMI1 and BMI2 enabled.
 * It can only be loaded on a CPU that supports all three.
 *
 * - It hashes 4 leaves at a time with AVX2 (see keccak_x4_avx2.c).
 * - The rest of the code (the scalar Keccak used for the first chunk,
 *   the leftover leaves and the final node) gets faster with BMI1 and BMI2,
 *   as in keccak_avx2_bmi2.c.
 *
 * See KECCAK_K12.txt for which file includes which, and the resulting modules.
 */

#define K12_MODULE k12_avx2_bmi2
#define K12_AVX2
#include "k12.c"
