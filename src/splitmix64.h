/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * SplitMix64, a simple generator: the elliptic curves use it to expand
 * the random seed of a scalar multiplication (the blinding of the scalar,
 * the randomization of the coordinates). It is not meant for anything
 * else: the seed itself comes from the RNG of the caller.
 */

#ifndef SPLITMIX64_H
#define SPLITMIX64_H

#include "common.h"

/** The next value of the generator, which updates the state **/
static inline uint64_t splitmix64_next(uint64_t *state)
{
    uint64_t z;

    *state += 0x9E3779B97F4A7C15ULL;
    z = *state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

#endif
