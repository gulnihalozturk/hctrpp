/*
 * HCTR++ reference implementation (x86-64, AES-NI + PCLMULQDQ).
 *
 * Implements HCTR++ as specified in "HCTR++: A Beyond Birthday Bound Secure
 * HCTR2 Variant" (Ozturk, Kocak, Yayla, ePrint 2026/383), Figure 4.
 * The concrete instantiation (POLYVAL256, input encodings, endianness) is
 * fixed by the executable specification in python/hctrpp.py; see README.md.
 *
 * MIT license.
 */
#ifndef HCTRPP_H_
#define HCTRPP_H_

#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>

typedef struct {
    __m128i lo, hi; /* bits 0..127 / 128..255, little-endian byte strings */
} gf256;

typedef struct {
    gf256 p[4]; /* hash key powers h^(j+1) x^(-256 j), Montgomery form */
} hctrpp_hkey;

typedef struct {
    hctrpp_hkey hk1, hk2, hk12; /* hash keys h1, h2, h1^h2 */
    gf256 kp;                   /* re-keying hash key Kbar */
    gf256 ks1;                  /* precomputed Horner state of H_Kbar(r) after
                                   the length block, with the 0x01 padding bit
                                   of the second block folded in */
} hctrpp_ctx;

/* One-time subkey derivation from the 16-byte AES-128 key. Returns 0. */
int hctrpp_init(hctrpp_ctx *ctx, const uint8_t key[16]);

/*
 * Length-preserving tweakable encryption/decryption.
 * in/out may alias only if equal. len >= 16 bytes; tweak_len arbitrary.
 * Returns 0 on success, <0 on invalid input.
 */
int hctrpp_encrypt(const hctrpp_ctx *ctx, const uint8_t *pt, size_t len,
                   const uint8_t *tweak, size_t tweak_len, uint8_t *ct);
int hctrpp_decrypt(const hctrpp_ctx *ctx, const uint8_t *ct, size_t len,
                   const uint8_t *tweak, size_t tweak_len, uint8_t *pt);

#endif /* HCTRPP_H_ */
