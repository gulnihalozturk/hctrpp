/*
    MIT license
    Copyright (C) 2025 Intel Corporation
    SPDX-License-Identifier: MIT

    Benchmark build of the upstream zeroize.h: zeroization compiled out
    (static inline no-op) so that BBB-DDD-AES is measured under the same
    conditions as the other schemes in the comparison, which perform no
    zeroization. Equivalent to building upstream with -DZEROIZE_SECRETS off,
    minus the residual cross-TU call overhead.
*/
#ifndef ZEROIZE_H_
#define ZEROIZE_H_

#include <stddef.h>

static inline void zeroize_secret(void* secret, size_t secret_len)
{
    (void)secret;
    (void)secret_len;
}

#endif /* ZEROIZE_H_ */
