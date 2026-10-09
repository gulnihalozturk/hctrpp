/*
 * Plain-C benchmark interface to CHCTR2 and HCTR2-TwKD (ePrint 2026/085),
 * implemented by the sibling checkout ../CHCTR-HCTR2TwKD.  Keeps that
 * repository's headers (and their macros) out of benchmark.c.
 *
 * aes_keylen selects the instantiation: 32 = AES-256 as specified upstream,
 * 16 = the AES-128 benchmark variant (see chctr_glue.c).  All calls use the
 * accelerated (AES-NI / PCLMULQDQ) paths.
 *
 * MIT license.
 */
#ifndef CHCTR_GLUE_H
#define CHCTR_GLUE_H

#include <stddef.h>
#include <stdint.h>

typedef struct bench_chctr2 bench_chctr2;
typedef struct bench_twkd bench_twkd;

/* CHCTR2: key = K1 || K2, 2 * aes_keylen bytes; any tweak length. */
bench_chctr2 *bench_chctr2_new(void);
void bench_chctr2_free(bench_chctr2 *c);
void bench_chctr2_setkey(bench_chctr2 *c, const uint8_t *key,
                         size_t aes_keylen);
void bench_chctr2_encrypt(const bench_chctr2 *c, const uint8_t *src,
                          size_t len, const uint8_t *twk, size_t twklen,
                          uint8_t *dst);
void bench_chctr2_decrypt(const bench_chctr2 *c, const uint8_t *src,
                          size_t len, const uint8_t *twk, size_t twklen,
                          uint8_t *dst);

/* HCTR2-TwKD: KDF key L, aes_keylen bytes; 16-byte tweak with the top two
 * bits of twk[0] zero (they carry the CENC prefix). */
bench_twkd *bench_twkd_new(void);
void bench_twkd_free(bench_twkd *c);
void bench_twkd_setkey(bench_twkd *c, const uint8_t *key, size_t aes_keylen);
void bench_twkd_encrypt(const bench_twkd *c, const uint8_t *src, size_t len,
                        const uint8_t twk[16], uint8_t *dst);
void bench_twkd_decrypt(const bench_twkd *c, const uint8_t *src, size_t len,
                        const uint8_t twk[16], uint8_t *dst);

/* Validates this build (frozen upstream vectors, accelerated vs generic
 * paths, cascade structure); prints a summary and returns the number of
 * failed checks. */
int bench_chctr_selftest(void);

#endif
