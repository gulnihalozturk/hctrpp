/*
 * Benchmark adapter for CHCTR2 and HCTR2-TwKD (Chen et al., ePrint
 * 2026/085), compiled against the sibling checkout ../CHCTR-HCTR2TwKD.
 *
 * Instantiations:
 *
 * - AES-256 (aes_keylen 32): exactly the upstream code, chctr2_setkey /
 *   chctr2_crypt and twkd_setkey / twkd_crypt, as specified in the paper
 *   and checked against its frozen v1 vectors.
 * - AES-128 (aes_keylen 16): benchmark variants key-size-matched to HCTR++,
 *   not part of the paper.  CHCTR2 with K1 || K2 two AES-128 keys
 *   (chctr2_crypt is key-size agnostic; only setkey fixes AES-256).
 *   HCTR2-TwKD with an AES-128 KDF key L and the one-block CENC output
 *   K = E_L(00||T) ^ E_L(01||T) as the AES-128 HCTR2 key: the first half
 *   of the upstream F_L(T), so 2 instead of 3 AES calls per message.
 *
 * MIT license.
 */
#ifdef _WIN32
#include <malloc.h>
#endif

#include "chctr2.h"
#include "conformance_vectors.h"
#include "hctr2.h"
#include "hctr2_format.h"
#include "hctr2_twkd.h"
#include "chctr_glue.h"

/* util.h's ASSERT target; upstream defines it in cipherbench.c */
__cold __noreturn void assertion_failed(const char *expr, const char *file,
                                        int line)
{
    fflush(stdout);
    fprintf(stderr, "Assertion failed: %s at %s:%d\n", expr, file, line);
    abort();
}

struct bench_chctr2 {
    struct chctr2_ctx ctx;
};

struct bench_twkd {
    struct hctr2_twkd_ctx ctx;
};

/* chctr2_setkey with the AES key length as a parameter; AES-256 goes to
 * the upstream function unchanged. */
static void chctr2_setkey_len(struct chctr2_ctx *ctx, const u8 *key,
                              size_t aes_keylen, bool simd)
{
    u8 h1_raw[16] = { 0 }, h2_raw[16] = { 0 };
    le128 tmp;
    int i;

    ASSERT(aes_keylen == AES_KEYSIZE_128 || aes_keylen == AES_KEYSIZE_256);
    if (aes_keylen == AES_KEYSIZE_256) {
        chctr2_setkey(ctx, key, simd);
        return;
    }

    aes_setkey(&ctx->aes1, key, (int)aes_keylen);
    aes_setkey(&ctx->aes2, key + aes_keylen, (int)aes_keylen);
    aes_encrypt(&ctx->aes1, h1_raw, h1_raw, simd);
    aes_encrypt(&ctx->aes2, h2_raw, h2_raw, simd);
    memset(ctx->L1, 0, 16);
    ctx->L1[0] = 0x01;
    aes_encrypt(&ctx->aes1, ctx->L1, ctx->L1, simd);
    memset(ctx->L2, 0, 16);
    ctx->L2[0] = 0x01;
    aes_encrypt(&ctx->aes2, ctx->L2, ctx->L2, simd);

    polyval_xor_setkey(&ctx->hx, h1_raw, h2_raw, simd);

    ctx->default_tweak_len = HCTR2_DEFAULT_TWEAK_LEN;
    for (i = 0; i < 2; i++) {
        polyval_init(&ctx->init1[i]);
        polyval_init(&ctx->init2[i]);
        hctr2_format_length_block(&tmp, ctx->default_tweak_len, i != 0);
        polyval_update(&ctx->init1[i], &ctx->hx.h1, (u8 *)&tmp, 1, simd);
        polyval_update(&ctx->init2[i], &ctx->hx.h2, (u8 *)&tmp, 1, simd);
    }
}

static void twkd_setkey_len(struct hctr2_twkd_ctx *ctx, const u8 *key,
                            size_t aes_keylen)
{
    ASSERT(aes_keylen == AES_KEYSIZE_128 || aes_keylen == AES_KEYSIZE_256);
    if (aes_keylen == AES_KEYSIZE_256)
        twkd_setkey(ctx, key);
    else
        aes_setkey(&ctx->kdf_aes, key, AES_KEYSIZE_128);
}

/* K = E_L(00||T) ^ E_L(01||T), the first half of upstream twkd_derive */
static void twkd128_derive(const struct hctr2_twkd_ctx *ctx, const u8 *tweak,
                           u8 subkey[16], bool simd)
{
    u8 in[16], e0[16], e1[16];

    ASSERT((tweak[0] & 0xc0) == 0);
    memcpy(in, tweak, 16);
    aes_encrypt(&ctx->kdf_aes, e0, in, simd);
    in[0] |= 0x40;
    aes_encrypt(&ctx->kdf_aes, e1, in, simd);
    xor(subkey, e0, e1, 16);
}

/* twkd_crypt with the AES-128 derivation; same per-message structure */
static void twkd_crypt_len(const struct hctr2_twkd_ctx *ctx, u8 *dst,
                           const u8 *src, size_t nbytes, const u8 *tweak,
                           bool encrypt, bool simd)
{
    struct hctr2_ctx hctr2;
    u8 subkey[16];

    if (ctx->kdf_aes.aes_ctx.key_length == AES_KEYSIZE_256) {
        twkd_crypt(ctx, dst, src, nbytes, tweak, encrypt, simd);
        return;
    }
    twkd128_derive(ctx, tweak, subkey, simd);
    hctr2_setkey(&hctr2, subkey, AES_KEYSIZE_128, simd);
    hctr2_crypt(&hctr2, dst, src, nbytes, tweak, 0, encrypt, simd);
}

static void *alloc_aligned(size_t n)
{
#ifdef _WIN32
    void *p = _aligned_malloc(n, 64);
#else
    void *p = aligned_alloc(64, (n + 63) & ~(size_t)63);
#endif
    ASSERT(p != NULL);
    return p;
}

static void free_aligned(void *p)
{
#ifdef _WIN32
    _aligned_free(p);
#else
    free(p);
#endif
}

bench_chctr2 *bench_chctr2_new(void)
{
    return alloc_aligned(sizeof(bench_chctr2));
}

void bench_chctr2_free(bench_chctr2 *c)
{
    free_aligned(c);
}

void bench_chctr2_setkey(bench_chctr2 *c, const uint8_t *key,
                         size_t aes_keylen)
{
    chctr2_setkey_len(&c->ctx, key, aes_keylen, true);
}

void bench_chctr2_encrypt(const bench_chctr2 *c, const uint8_t *src,
                          size_t len, const uint8_t *twk, size_t twklen,
                          uint8_t *dst)
{
    chctr2_crypt(&c->ctx, dst, src, len, twk, twklen, true, true);
}

void bench_chctr2_decrypt(const bench_chctr2 *c, const uint8_t *src,
                          size_t len, const uint8_t *twk, size_t twklen,
                          uint8_t *dst)
{
    chctr2_crypt(&c->ctx, dst, src, len, twk, twklen, false, true);
}

bench_twkd *bench_twkd_new(void)
{
    return alloc_aligned(sizeof(bench_twkd));
}

void bench_twkd_free(bench_twkd *c)
{
    free_aligned(c);
}

void bench_twkd_setkey(bench_twkd *c, const uint8_t *key, size_t aes_keylen)
{
    twkd_setkey_len(&c->ctx, key, aes_keylen);
}

void bench_twkd_encrypt(const bench_twkd *c, const uint8_t *src, size_t len,
                        const uint8_t twk[16], uint8_t *dst)
{
    twkd_crypt_len(&c->ctx, dst, src, len, twk, true, true);
}

void bench_twkd_decrypt(const bench_twkd *c, const uint8_t *src, size_t len,
                        const uint8_t twk[16], uint8_t *dst)
{
    twkd_crypt_len(&c->ctx, dst, src, len, twk, false, true);
}

/* ---- self-test ----
 * The upstream conformance suite cannot exercise the accelerated paths on
 * Windows (its simd_supported() is false there), and on Windows this build
 * reaches the assembly through the ABI thunks and rewritten sections, so
 * the benchmark checks its own build before timing anything. */

static int checks, failures;

static void check(bool ok, const char *what, const char *id)
{
    checks++;
    if (!ok) {
        failures++;
        fprintf(stderr, "self-test FAIL: %s %s\n", what, id);
    }
}

static uint64_t prng_state = 0x243f6a8885a308d3ULL;

static void prng_fill(u8 *p, size_t n)
{
    while (n--) {
        uint64_t z = (prng_state += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        *p++ = (u8)(z ^ (z >> 31));
    }
}

#define TEST_MAXLEN 65536

static struct chctr2_ctx t_c1, t_c2;
static struct hctr2_twkd_ctx t_tw;
static struct hctr2_ctx t_h1, t_h2;
static u8 t_pt[TEST_MAXLEN], t_ct[TEST_MAXLEN], t_ref[TEST_MAXLEN],
    t_tmp[TEST_MAXLEN];

/* Frozen v1 vectors (AES-256), accelerated path, both directions */
static void test_frozen(void)
{
    for (size_t i = 0; i < chctr2_conf_tv_count; i++) {
        const struct conf_vec *v = &chctr2_conf_tv[i];

        ASSERT(v->key_len == 64 && v->len <= TEST_MAXLEN);
        chctr2_setkey(&t_c1, v->key, true);
        chctr2_crypt(&t_c1, t_ct, v->plaintext, v->len, v->tweak,
                     v->tweak_len, true, true);
        check(!memcmp(t_ct, v->ciphertext, v->len), "CHCTR2 KAT enc", v->id);
        chctr2_crypt(&t_c1, t_ct, v->ciphertext, v->len, v->tweak,
                     v->tweak_len, false, true);
        check(!memcmp(t_ct, v->plaintext, v->len), "CHCTR2 KAT dec", v->id);
    }
    for (size_t i = 0; i < twkd_conf_tv_count; i++) {
        const struct conf_vec *v = &twkd_conf_tv[i];

        ASSERT(v->key_len == 32 && v->tweak_len == TWKD_TWEAK_LEN &&
               v->len <= TEST_MAXLEN);
        twkd_setkey(&t_tw, v->key);
        twkd_crypt(&t_tw, t_ct, v->plaintext, v->len, v->tweak, true, true);
        check(!memcmp(t_ct, v->ciphertext, v->len), "TwKD KAT enc", v->id);
        twkd_crypt(&t_tw, t_ct, v->ciphertext, v->len, v->tweak, false,
                   true);
        check(!memcmp(t_ct, v->plaintext, v->len), "TwKD KAT dec", v->id);
    }
}

static const size_t test_lens[] = { 16, 17, 31, 32, 33, 255, 256, 257,
                                    4096, 4111, TEST_MAXLEN };
static const size_t test_twklens[] = { 0, 1, 16, 17, 32 };

/* Accelerated vs generic C (aes_ti / gf128), and decryption round trip,
 * for one key size.  Covers the 128- and 256-bit XCTR assembly, AES-NI
 * ECB, POLYVAL update/mul and the merged-hash fast path. */
static void test_accel_vs_generic(size_t aes_keylen)
{
    u8 key[64], twk[32];
    char id[64];

    prng_fill(key, sizeof(key));
    chctr2_setkey_len(&t_c1, key, aes_keylen, true);
    chctr2_setkey_len(&t_c2, key, aes_keylen, false);
    twkd_setkey_len(&t_tw, key, aes_keylen);

    for (size_t i = 0; i < ARRAY_SIZE(test_lens); i++) {
        size_t len = test_lens[i];

        for (size_t j = 0; j < ARRAY_SIZE(test_twklens); j++) {
            size_t twklen = test_twklens[j];

            snprintf(id, sizeof(id), "AES-%zu len=%zu twk=%zu",
                     aes_keylen * 8, len, twklen);
            prng_fill(t_pt, len);
            prng_fill(twk, twklen);
            chctr2_crypt(&t_c1, t_ct, t_pt, len, twk, twklen, true, true);
            chctr2_crypt(&t_c2, t_ref, t_pt, len, twk, twklen, true, false);
            check(!memcmp(t_ct, t_ref, len), "CHCTR2 accel vs generic", id);
            chctr2_crypt(&t_c1, t_tmp, t_ct, len, twk, twklen, false, true);
            check(!memcmp(t_tmp, t_pt, len), "CHCTR2 round trip", id);
        }

        snprintf(id, sizeof(id), "AES-%zu len=%zu", aes_keylen * 8, len);
        prng_fill(t_pt, len);
        prng_fill(twk, 16);
        twk[0] &= 0x3f;
        twkd_crypt_len(&t_tw, t_ct, t_pt, len, twk, true, true);
        twkd_crypt_len(&t_tw, t_ref, t_pt, len, twk, true, false);
        check(!memcmp(t_ct, t_ref, len), "TwKD accel vs generic", id);
        twkd_crypt_len(&t_tw, t_tmp, t_ct, len, twk, false, true);
        check(!memcmp(t_tmp, t_pt, len), "TwKD round trip", id);
    }
}

/* CHCTR2 = HCTR2[K2] o HCTR2[K1] with upstream black-box HCTR2, and the
 * AES-128 TwKD subkey = first half of upstream twkd_derive under the same
 * AES-128 L. */
static void test_structure(size_t aes_keylen)
{
    u8 key[64], twk[32], sub[32], sub128[16];
    char id[64];

    prng_fill(key, sizeof(key));
    chctr2_setkey_len(&t_c1, key, aes_keylen, true);
    hctr2_setkey(&t_h1, key, aes_keylen, true);
    hctr2_setkey(&t_h2, key + aes_keylen, aes_keylen, true);
    for (size_t i = 0; i < ARRAY_SIZE(test_lens); i++) {
        size_t len = test_lens[i];
        size_t twklen = test_twklens[i % ARRAY_SIZE(test_twklens)];

        snprintf(id, sizeof(id), "AES-%zu len=%zu twk=%zu", aes_keylen * 8,
                 len, twklen);
        prng_fill(t_pt, len);
        prng_fill(twk, twklen);
        chctr2_crypt(&t_c1, t_ct, t_pt, len, twk, twklen, true, true);
        hctr2_crypt(&t_h1, t_tmp, t_pt, len, twk, twklen, true, true);
        hctr2_crypt(&t_h2, t_ref, t_tmp, len, twk, twklen, true, true);
        check(!memcmp(t_ct, t_ref, len), "CHCTR2 = HCTR2 cascade", id);
    }

    if (aes_keylen == AES_KEYSIZE_128) {
        aes_setkey(&t_tw.kdf_aes, key, AES_KEYSIZE_128);
        for (int i = 0; i < 8; i++) {
            prng_fill(twk, 16);
            twk[0] &= 0x3f;
            twkd_derive(&t_tw, twk, sub, true);
            twkd128_derive(&t_tw, twk, sub128, true);
            snprintf(id, sizeof(id), "#%d", i);
            check(!memcmp(sub, sub128, 16), "TwKD-128 KDF = F_L(T)[0:16]",
                  id);
        }
    }
}

int bench_chctr_selftest(void)
{
    checks = failures = 0;
    test_frozen();
    test_accel_vs_generic(AES_KEYSIZE_128);
    test_accel_vs_generic(AES_KEYSIZE_256);
    test_structure(AES_KEYSIZE_128);
    test_structure(AES_KEYSIZE_256);
    printf("CHCTR2/HCTR2-TwKD self-test: %d checks (%zu + %zu frozen "
           "vectors), %d failed\n",
           checks, chctr2_conf_tv_count, twkd_conf_tv_count, failures);
    return failures;
}
