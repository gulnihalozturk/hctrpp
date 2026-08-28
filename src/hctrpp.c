/*
 * HCTR++ reference implementation (x86-64, AES-NI + PCLMULQDQ).
 * See include/hctrpp.h and README.md for the specification details.
 *
 * The AES-128 key schedule / round function helpers and the 128-bit
 * carry-less multiplication pattern are adapted from Intel's ddd-aes
 * reference implementation (MIT license, Copyright (C) 2025 Intel
 * Corporation, https://github.com/intel/ddd-aes).
 *
 * MIT license.
 */
#include <string.h>
#include "../include/hctrpp.h"

#if !defined(__AES__) || !defined(__PCLMUL__)
#error "Compile with -maes -mpclmul (or -march=native on a supporting CPU)"
#endif

/* ------------------------------------------------------------ GF(2^256) --
 * Field: GF(2^256) mod P(x) = x^256 + x^254 + x^251 + x^246 + 1
 * (the reciprocal of the Rijndael-256/GHASH-256 polynomial, hence
 * irreducible). Elements are 256-bit little-endian strings (bit i <-> x^i),
 * kept as gf256 { lo = bits 0..127, hi = bits 128..255 }.
 */

/* 128x128 -> 256 carry-less multiply (schoolbook, 4x PCLMUL). */
static inline void clmul128(__m128i a, __m128i b, __m128i *rlo, __m128i *rhi)
{
    __m128i t1 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i t2 = _mm_clmulepi64_si128(a, b, 0x10);
    __m128i t3 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i t4 = _mm_clmulepi64_si128(a, b, 0x11);
    t2 = _mm_xor_si128(t2, t3);
    *rlo = _mm_xor_si128(t1, _mm_slli_si128(t2, 8));
    *rhi = _mm_xor_si128(t4, _mm_srli_si128(t2, 8));
}

/* 256x256 -> 512 carry-less product (Karatsuba over 128-bit halves).
 * out lo = bits 0..255, out hi = bits 256..511. */
static inline void clmul256(gf256 a, gf256 b, gf256 *lo, gf256 *hi)
{
    __m128i z0, z1, z2, z3, m0, m1;
    clmul128(a.lo, b.lo, &z0, &z1);
    clmul128(a.hi, b.hi, &z2, &z3);
    clmul128(_mm_xor_si128(a.lo, a.hi), _mm_xor_si128(b.lo, b.hi), &m0, &m1);
    m0 = _mm_xor_si128(m0, _mm_xor_si128(z0, z2));
    m1 = _mm_xor_si128(m1, _mm_xor_si128(z1, z3));
    lo->lo = z0;
    lo->hi = _mm_xor_si128(z1, m0);
    hi->lo = _mm_xor_si128(z2, m1);
    hi->hi = z3;
}

/* 256x256 -> 256 Montgomery product a*b*x^-256 mod P: the POLYVAL dot
 * operation of RFC 8452 lifted to GF(2^256). This is what the reciprocal
 * polynomial buys: 1 == x^256 + C*x^192 (mod P) with C = x^62 + x^59 + x^54,
 * so a low 64-bit word t of the product folds upward as
 *     t -> t*x^256 ^ (t*C)*x^192
 * -- one CLMUL by the constant C, no bit shifts. Folding the four low words
 * of the 512-bit product T = (t0..t7) two at a time (words 0,1 first, then
 * the updated words 2,3) leaves words 4..7 = T*x^-256 mod P, degree < 256.
 * Cost: 4 CLMUL on top of the 12 for a*b. */
static inline gf256 gf256_mont(gf256 a, gf256 b)
{
    const __m128i C = _mm_set_epi64x(0, 0x4840000000000000LL);
    gf256 t, u; /* T = a*b: t = words 0..3, u = words 4..7 */

    clmul256(a, b, &t, &u);
    /* t0 -> word 4, t0*C -> words 3,4;  t1 -> word 5, t1*C -> words 4,5 */
    __m128i a0 = _mm_clmulepi64_si128(t.lo, C, 0x00);
    __m128i a1 = _mm_clmulepi64_si128(t.lo, C, 0x01);
    t.hi = _mm_xor_si128(t.hi, _mm_slli_si128(a0, 8));
    u.lo = _mm_xor_si128(u.lo, _mm_xor_si128(
               t.lo, _mm_xor_si128(a1, _mm_srli_si128(a0, 8))));
    /* t2 -> word 6, t2*C -> words 5,6;  t3 -> word 7, t3*C -> words 6,7 */
    __m128i b0 = _mm_clmulepi64_si128(t.hi, C, 0x00);
    __m128i b1 = _mm_clmulepi64_si128(t.hi, C, 0x01);
    u.lo = _mm_xor_si128(u.lo, _mm_slli_si128(b0, 8));
    u.hi = _mm_xor_si128(u.hi, _mm_xor_si128(
               t.hi, _mm_xor_si128(b1, _mm_srli_si128(b0, 8))));
    return u;
}

#if defined(__VAES__) && defined(__VPCLMULQDQ__) && defined(__AVX512BW__)
#define HCTRPP_VAES 1
/* Four independent GF(2^256) multiplications, one per 128-bit zmm lane;
 * the exact per-lane analog of clmul128/gf256_mont above. */
static inline void clmul128_x4(__m512i a, __m512i b, __m512i *rlo,
                               __m512i *rhi)
{
    __m512i t1 = _mm512_clmulepi64_epi128(a, b, 0x00);
    __m512i t2 = _mm512_clmulepi64_epi128(a, b, 0x10);
    __m512i t3 = _mm512_clmulepi64_epi128(a, b, 0x01);
    __m512i t4 = _mm512_clmulepi64_epi128(a, b, 0x11);
    t2 = _mm512_xor_si512(t2, t3);
    *rlo = _mm512_xor_si512(t1, _mm512_bslli_epi128(t2, 8));
    *rhi = _mm512_xor_si512(t4, _mm512_bsrli_epi128(t2, 8));
}

/* 256x256 -> 512 per lane; out (r0,r1)=bits 0..255, (r2,r3)=bits 256..511. */
static inline void clmul256_x4(__m512i alo, __m512i ahi, __m512i blo,
                               __m512i bhi, __m512i *r0, __m512i *r1,
                               __m512i *r2, __m512i *r3)
{
    __m512i z0, z1, z2, z3, m0, m1;
    clmul128_x4(alo, blo, &z0, &z1);
    clmul128_x4(ahi, bhi, &z2, &z3);
    clmul128_x4(_mm512_xor_si512(alo, ahi), _mm512_xor_si512(blo, bhi),
                &m0, &m1);
    m0 = _mm512_xor_si512(m0, _mm512_xor_si512(z0, z2));
    m1 = _mm512_xor_si512(m1, _mm512_xor_si512(z1, z3));
    *r0 = z0;
    *r1 = _mm512_xor_si512(z1, m0);
    *r2 = _mm512_xor_si512(z2, m1);
    *r3 = z3;
}

/* Per-lane analog of gf256_mont (see there). */
static inline void gf256_mont_x4(__m512i alo, __m512i ahi, __m512i blo,
                                 __m512i bhi, __m512i *rlo, __m512i *rhi)
{
    const __m512i C = _mm512_broadcast_i32x4(
        _mm_set_epi64x(0, 0x4840000000000000LL));
    __m512i t0, t1, t2, t3; /* T = a*b per lane: words (0,1) (2,3) (4,5) (6,7) */

    clmul256_x4(alo, ahi, blo, bhi, &t0, &t1, &t2, &t3);
    __m512i a0 = _mm512_clmulepi64_epi128(t0, C, 0x00);
    __m512i a1 = _mm512_clmulepi64_epi128(t0, C, 0x01);
    t1 = _mm512_xor_si512(t1, _mm512_bslli_epi128(a0, 8));
    t2 = _mm512_xor_si512(t2, _mm512_xor_si512(
             t0, _mm512_xor_si512(a1, _mm512_bsrli_epi128(a0, 8))));
    __m512i b0 = _mm512_clmulepi64_epi128(t1, C, 0x00);
    __m512i b1 = _mm512_clmulepi64_epi128(t1, C, 0x01);
    *rlo = _mm512_xor_si512(t2, _mm512_bslli_epi128(b0, 8));
    *rhi = _mm512_xor_si512(t3, _mm512_xor_si512(
               t1, _mm512_xor_si512(b1, _mm512_bsrli_epi128(b0, 8))));
}
#endif /* HCTRPP_VAES */

/* -------------------------------------------------------------- AES-128 -- */

/* SubWord(RotWord(w3)) ^ rcon, broadcast to all four dwords, computed with
 * pshufb + aesenclast instead of aeskeygenassist: on a state whose columns
 * are all equal ShiftRows is the identity, so aesenclast(x, rcon) yields
 * SubBytes(x) ^ rcon. Faster than aeskeygenassist on common cores. */
#define KS_ROTBC _mm_setr_epi8(13, 14, 15, 12, 13, 14, 15, 12, \
                               13, 14, 15, 12, 13, 14, 15, 12)
#define KS_G(k, rcon) \
    _mm_aesenclast_si128(_mm_shuffle_epi8((k), KS_ROTBC), _mm_set1_epi32(rcon))

static inline __m128i ks_fold(__m128i k, __m128i g)
{
    __m128i t;
    t = _mm_slli_si128(k, 4);
    k = _mm_xor_si128(k, t);
    t = _mm_slli_si128(t, 4);
    k = _mm_xor_si128(k, t);
    t = _mm_slli_si128(t, 4);
    k = _mm_xor_si128(k, t);
    return _mm_xor_si128(k, g);
}

#define KS1_ROUND(rcon, idx) \
    (rk[idx] = k0 = ks_fold(k0, KS_G(k0, rcon)))

static inline void aes128_expand(__m128i key, __m128i rk[11])
{
    __m128i k0 = key;
    rk[0] = k0;
    KS1_ROUND(0x01, 1); KS1_ROUND(0x02, 2); KS1_ROUND(0x04, 3);
    KS1_ROUND(0x08, 4); KS1_ROUND(0x10, 5); KS1_ROUND(0x20, 6);
    KS1_ROUND(0x40, 7); KS1_ROUND(0x80, 8); KS1_ROUND(0x1b, 9);
    KS1_ROUND(0x36, 10);
}

/* Four independent AES-128 key schedules, interleaved per round so the
 * aeskeygenassist chains overlap. */
#define KS4_ROUND(rcon, idx) do { \
    rk4[0][idx] = k0 = ks_fold(k0, KS_G(k0, rcon)); \
    rk4[1][idx] = k1 = ks_fold(k1, KS_G(k1, rcon)); \
    rk4[2][idx] = k2 = ks_fold(k2, KS_G(k2, rcon)); \
    rk4[3][idx] = k3 = ks_fold(k3, KS_G(k3, rcon)); \
} while (0)

static inline void aes128_expand_x4(const __m128i key[4], __m128i rk4[4][11])
{
    __m128i k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3];
    rk4[0][0] = k0; rk4[1][0] = k1; rk4[2][0] = k2; rk4[3][0] = k3;
    KS4_ROUND(0x01, 1); KS4_ROUND(0x02, 2); KS4_ROUND(0x04, 3);
    KS4_ROUND(0x08, 4); KS4_ROUND(0x10, 5); KS4_ROUND(0x20, 6);
    KS4_ROUND(0x40, 7); KS4_ROUND(0x80, 8); KS4_ROUND(0x1b, 9);
    KS4_ROUND(0x36, 10);
}

static inline __m128i aes_enc_one(__m128i x, const __m128i rk[11])
{
    x = _mm_xor_si128(x, rk[0]);
    for (int r = 1; r < 10; r++)
        x = _mm_aesenc_si128(x, rk[r]);
    return _mm_aesenclast_si128(x, rk[10]);
}

/* Four blocks, each under its own round keys, interleaved. */
static inline void aes_enc_x4(__m128i b[4], const __m128i rk4[4][11])
{
    for (int k = 0; k < 4; k++)
        b[k] = _mm_xor_si128(b[k], rk4[k][0]);
    for (int r = 1; r < 10; r++)
        for (int k = 0; k < 4; k++)
            b[k] = _mm_aesenc_si128(b[k], rk4[k][r]);
    for (int k = 0; k < 4; k++)
        b[k] = _mm_aesenclast_si128(b[k], rk4[k][10]);
}

#ifdef HCTRPP_VAES
/* Four independent AES-128 key schedules, one per zmm lane (per-lane analog
 * of KS_G/ks_fold), immediately consumed by a four-lane AES encryption. */
#define KS512_ROUND(rcon, idx) do { \
    __m512i g_ = _mm512_aesenclast_epi128( \
        _mm512_shuffle_epi8(kz, rotbc), _mm512_set1_epi32(rcon)); \
    __m512i t_ = _mm512_bslli_epi128(kz, 4); \
    kz = _mm512_xor_si512(kz, t_); \
    t_ = _mm512_bslli_epi128(t_, 4); \
    kz = _mm512_xor_si512(kz, t_); \
    t_ = _mm512_bslli_epi128(t_, 4); \
    kz = _mm512_xor_si512(kz, t_); \
    kz = _mm512_xor_si512(kz, g_); \
    rkz[idx] = kz; \
} while (0)

static inline __m512i aes128_x4lanes(__m512i uz, __m512i blocks)
{
    const __m512i rotbc = _mm512_broadcast_i32x4(KS_ROTBC);
    __m512i rkz[11], kz = uz;
    rkz[0] = kz;
    KS512_ROUND(0x01, 1); KS512_ROUND(0x02, 2); KS512_ROUND(0x04, 3);
    KS512_ROUND(0x08, 4); KS512_ROUND(0x10, 5); KS512_ROUND(0x20, 6);
    KS512_ROUND(0x40, 7); KS512_ROUND(0x80, 8); KS512_ROUND(0x1b, 9);
    KS512_ROUND(0x36, 10);

    __m512i x = _mm512_xor_si512(blocks, rkz[0]);
    for (int r = 1; r < 10; r++)
        x = _mm512_aesenc_epi128(x, rkz[r]);
    return _mm512_aesenclast_epi128(x, rkz[10]);
}
#endif /* HCTRPP_VAES */

/* Single-block decryption via the equivalent inverse cipher. */
static inline __m128i aes_dec_one(__m128i x, const __m128i rk[11])
{
    x = _mm_xor_si128(x, rk[10]);
    for (int r = 9; r >= 1; r--)
        x = _mm_aesdec_si128(x, _mm_aesimc_si128(rk[r]));
    return _mm_aesdeclast_si128(x, rk[0]);
}

/* --------------------------------------------------------------- hash H --
 * H_h(T, M) = POLYVAL256(h, bin256(2|T| + 2 [+1]) || pad(T) || M') where
 * M' = M if |M| is a multiple of 32 bytes, else pad(M || 0x01).
 * gf256_mont(s, h) = s*h*x^-256 is exactly the RFC 8452 dot operation, so
 * one call per 32-byte block with the raw key h.
 */
static inline gf256 hash_absorb(gf256 s, gf256 hp, const uint8_t *p)
{
    s.lo = _mm_xor_si128(s.lo, _mm_loadu_si128((const __m128i *)p));
    s.hi = _mm_xor_si128(s.hi, _mm_loadu_si128((const __m128i *)(p + 16)));
    return gf256_mont(s, hp);
}

static gf256 hctrpp_hash(const hctrpp_hkey *hk, const uint8_t *tweak,
                         size_t tlen, const uint8_t *msg, size_t mlen)
{
    size_t i;
    const gf256 hp = hk->p[0];
    int awkward = (mlen % 32) != 0;
    uint64_t lengthint = (uint64_t)tlen * 16 + 2 + (awkward ? 1 : 0);

    gf256 s;
    s.lo = _mm_set_epi64x(0, (long long)lengthint);
    s.hi = _mm_setzero_si128();
    s = gf256_mont(s, hp);

    size_t tfull = tlen & ~(size_t)31;
    for (i = 0; i < tfull; i += 32)
        s = hash_absorb(s, hp, tweak + i);
    if (tlen & 31) {
        uint8_t buf[32] = { 0 };
        memcpy(buf, tweak + tfull, tlen & 31);
        s = hash_absorb(s, hp, buf);
    }

    size_t mfull = mlen & ~(size_t)31;
    i = 0;
#ifdef HCTRPP_VAES
    /* Aggregated evaluation, four 32-byte blocks per step:
     * S <- (S^m1)*hp^4 ^ m2*hp^3 ^ m3*hp^2 ^ m4*hp, all four products in
     * one lane-parallel multiply, then a horizontal XOR fold. */
    if (mfull >= 128) {
        __m512i klo = _mm512_zextsi128_si512(hk->p[3].lo);
        klo = _mm512_inserti32x4(klo, hk->p[2].lo, 1);
        klo = _mm512_inserti32x4(klo, hk->p[1].lo, 2);
        klo = _mm512_inserti32x4(klo, hk->p[0].lo, 3);
        __m512i khi = _mm512_zextsi128_si512(hk->p[3].hi);
        khi = _mm512_inserti32x4(khi, hk->p[2].hi, 1);
        khi = _mm512_inserti32x4(khi, hk->p[1].hi, 2);
        khi = _mm512_inserti32x4(khi, hk->p[0].hi, 3);
        for (; i + 128 <= mfull; i += 128) {
            __m512i d0 = _mm512_loadu_si512((const void *)(msg + i));
            __m512i d1 = _mm512_loadu_si512((const void *)(msg + i + 64));
            __m512i alo = _mm512_shuffle_i64x2(d0, d1, 0x88);
            __m512i ahi = _mm512_shuffle_i64x2(d0, d1, 0xdd);
            alo = _mm512_xor_si512(alo, _mm512_zextsi128_si512(s.lo));
            ahi = _mm512_xor_si512(ahi, _mm512_zextsi128_si512(s.hi));
            __m512i rlo, rhi;
            gf256_mont_x4(alo, ahi, klo, khi, &rlo, &rhi);
            __m256i flo = _mm256_xor_si256(
                _mm512_extracti64x4_epi64(rlo, 0),
                _mm512_extracti64x4_epi64(rlo, 1));
            __m256i fhi = _mm256_xor_si256(
                _mm512_extracti64x4_epi64(rhi, 0),
                _mm512_extracti64x4_epi64(rhi, 1));
            s.lo = _mm_xor_si128(_mm256_castsi256_si128(flo),
                                 _mm256_extracti128_si256(flo, 1));
            s.hi = _mm_xor_si128(_mm256_castsi256_si128(fhi),
                                 _mm256_extracti128_si256(fhi, 1));
        }
    }
#endif
    for (; i < mfull; i += 32)
        s = hash_absorb(s, hp, msg + i);
    if (awkward) {
        uint8_t buf[32] = { 0 };
        memcpy(buf, msg + mfull, mlen & 31);
        buf[mlen & 31] = 0x01;
        s = hash_absorb(s, hp, buf);
    }
    return s;
}

/* u || v = H_Kbar(r): the first hash block bin256(3) is constant, so its
 * Horner state (with the 0x01 pad bit of the second block folded in) is
 * precomputed in ctx->ks1 and each call costs a single field multiply. */
static inline gf256 rekey_uv(const hctrpp_ctx *ctx, __m128i r)
{
    gf256 e;
    e.lo = _mm_xor_si128(ctx->ks1.lo, r);
    e.hi = ctx->ks1.hi;
    return gf256_mont(e, ctx->kp);
}

/* ---------------------------------------------------------------- HCTR++ -- */

/* p[j] = h^(j+1) * x^(-256 j), so that mont(a, p[j]) = a * (h*x^-256)^(j+1):
 * the key powers of the POLYVAL Horner chain, in Montgomery form. */
static void hkey_powers(hctrpp_hkey *hk, gf256 hp)
{
    hk->p[0] = hp;
    hk->p[1] = gf256_mont(hp, hp);
    hk->p[2] = gf256_mont(hk->p[1], hp);
    hk->p[3] = gf256_mont(hk->p[2], hp);
}

int hctrpp_init(hctrpp_ctx *ctx, const uint8_t key[16])
{
    __m128i rk[11], e[6];
    gf256 h1, h2, kb, h12p, three, s1;

    if (!ctx || !key)
        return -1;

    aes128_expand(_mm_loadu_si128((const __m128i *)key), rk);
    for (int i = 0; i < 6; i++) /* h1 = E_K(bin(1))||E_K(bin(2)), ... */
        e[i] = aes_enc_one(_mm_set_epi64x(0, i + 1), rk);

    h1.lo = e[0]; h1.hi = e[1];
    h2.lo = e[2]; h2.hi = e[3];
    kb.lo = e[4]; kb.hi = e[5];

    hkey_powers(&ctx->hk1, h1);
    hkey_powers(&ctx->hk2, h2);
    h12p.lo = _mm_xor_si128(ctx->hk1.p[0].lo, ctx->hk2.p[0].lo);
    h12p.hi = _mm_xor_si128(ctx->hk1.p[0].hi, ctx->hk2.p[0].hi);
    hkey_powers(&ctx->hk12, h12p);
    ctx->kp = kb;

    three.lo = _mm_set_epi64x(0, 3);
    three.hi = _mm_setzero_si128();
    s1 = gf256_mont(three, ctx->kp);
    ctx->ks1.lo = s1.lo;
    ctx->ks1.hi = _mm_xor_si128(s1.hi, _mm_set_epi64x(0, 1));
    return 0;
}

static int crypt_core(const hctrpp_ctx *ctx, const uint8_t *in, size_t len,
                      const uint8_t *tweak, size_t tlen, uint8_t *out,
                      int decrypt)
{
    if (!ctx || !in || !out || len < 16 || (tlen && !tweak))
        return -1;

    const hctrpp_hkey *ha = decrypt ? &ctx->hk2 : &ctx->hk1;
    const hctrpp_hkey *hb = decrypt ? &ctx->hk1 : &ctx->hk2;
    const uint8_t *rest = in + 16;
    size_t rlen = len - 16;

    /* X1 = H_ha(T, rest); PP1 = B1 ^ X1[0:16]; re = X1[16:32] */
    gf256 x1 = hctrpp_hash(ha, tweak, tlen, rest, rlen);
    __m128i pp1 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)in), x1.lo);
    gf256 uve = rekey_uv(ctx, x1.hi);
    __m128i rke[11];
    aes128_expand(uve.lo, rke);
    __m128i cc = _mm_xor_si128(
        aes_enc_one(_mm_xor_si128(pp1, uve.hi), rke), uve.hi);

    /* r || J = H_{h1^h2}(T, CC) */
    uint8_t ccb[16];
    _mm_storeu_si128((__m128i *)ccb, cc);
    gf256 x = hctrpp_hash(&ctx->hk12, tweak, tlen, ccb, 16);
    __m128i r = x.lo, J = x.hi;

    /* CTR++: S_i = E_{u_i}(J_i ^ v_i) ^ v_i, u_i||v_i = H_Kbar(r ^ bin(i)) */
    size_t nfull = rlen / 16, tail = rlen % 16, i = 0;
#ifdef HCTRPP_VAES
    {
        const __m512i elo = _mm512_broadcast_i32x4(
            _mm_xor_si128(ctx->ks1.lo, r));
        const __m512i ehi = _mm512_broadcast_i32x4(ctx->ks1.hi);
        const __m512i kplo = _mm512_broadcast_i32x4(ctx->kp.lo);
        const __m512i kphi = _mm512_broadcast_i32x4(ctx->kp.hi);
        const __m512i jz = _mm512_broadcast_i32x4(J);
        for (; i + 4 <= nfull; i += 4) {
            __m512i ctrz = _mm512_set_epi64(
                0, (long long)(i + 4), 0, (long long)(i + 3),
                0, (long long)(i + 2), 0, (long long)(i + 1));
            __m512i uz, vz;
            gf256_mont_x4(_mm512_xor_si512(elo, ctrz), ehi, kplo, kphi,
                            &uz, &vz);
            __m512i blk = _mm512_xor_si512(_mm512_xor_si512(jz, ctrz), vz);
            __m512i s = _mm512_xor_si512(aes128_x4lanes(uz, blk), vz);
            _mm512_storeu_si512(
                (void *)(out + 16 + i * 16),
                _mm512_xor_si512(
                    _mm512_loadu_si512((const void *)(rest + i * 16)), s));
        }
    }
#else
    for (; i + 4 <= nfull; i += 4) {
        __m128i v[4], blk[4], rk4[4][11], u[4];
        for (int k = 0; k < 4; k++) {
            __m128i bi = _mm_set_epi64x(0, (long long)(i + k + 1));
            gf256 uv = rekey_uv(ctx, _mm_xor_si128(r, bi));
            u[k] = uv.lo;
            v[k] = uv.hi;
            blk[k] = _mm_xor_si128(_mm_xor_si128(J, bi), uv.hi);
        }
        aes128_expand_x4(u, rk4);
        aes_enc_x4(blk, rk4);
        for (int k = 0; k < 4; k++) {
            __m128i s = _mm_xor_si128(blk[k], v[k]);
            __m128i p = _mm_loadu_si128((const __m128i *)(rest + (i + k) * 16));
            _mm_storeu_si128((__m128i *)(out + 16 + (i + k) * 16),
                             _mm_xor_si128(p, s));
        }
    }
#endif
    for (; i < nfull + (tail ? 1 : 0); i++) {
        __m128i bi = _mm_set_epi64x(0, (long long)(i + 1));
        gf256 uv = rekey_uv(ctx, _mm_xor_si128(r, bi));
        __m128i rk[11];
        aes128_expand(uv.lo, rk);
        __m128i s = _mm_xor_si128(
            aes_enc_one(_mm_xor_si128(_mm_xor_si128(J, bi), uv.hi), rk),
            uv.hi);
        if (i < nfull) {
            __m128i p = _mm_loadu_si128((const __m128i *)(rest + i * 16));
            _mm_storeu_si128((__m128i *)(out + 16 + i * 16),
                             _mm_xor_si128(p, s));
        } else {
            uint8_t sb[16];
            _mm_storeu_si128((__m128i *)sb, s);
            for (size_t t = 0; t < tail; t++)
                out[16 + i * 16 + t] = rest[i * 16 + t] ^ sb[t];
        }
    }

    /* X2 = H_hb(T, out_rest); B1' = D_{u_d}(CC ^ v_d) ^ v_d ^ X2[0:16] */
    gf256 x2 = hctrpp_hash(hb, tweak, tlen, out + 16, rlen);
    gf256 uvd = rekey_uv(ctx, x2.hi);
    __m128i rkd[11];
    aes128_expand(uvd.lo, rkd);
    __m128i pp2 = _mm_xor_si128(
        aes_dec_one(_mm_xor_si128(cc, uvd.hi), rkd), uvd.hi);
    _mm_storeu_si128((__m128i *)out, _mm_xor_si128(pp2, x2.lo));
    return 0;
}

int hctrpp_encrypt(const hctrpp_ctx *ctx, const uint8_t *pt, size_t len,
                   const uint8_t *tweak, size_t tweak_len, uint8_t *ct)
{
    return crypt_core(ctx, pt, len, tweak, tweak_len, ct, 0);
}

int hctrpp_decrypt(const hctrpp_ctx *ctx, const uint8_t *ct, size_t len,
                   const uint8_t *tweak, size_t tweak_len, uint8_t *pt)
{
    return crypt_core(ctx, ct, len, tweak, tweak_len, pt, 1);
}
