/*
 * Three-way benchmark: HCTR++ vs BBB-DDD-AES vs PHCTR+ (HCTR+ with PHash).
 *
 * Methodology follows the HCTR_PLUS benchmark (Ghosh): for each data point,
 * take NSAMP=16 samples, each sample timing NRUNS=128 consecutive calls
 * after WARM=1024 cache-warming calls, feed one output byte back into the
 * input between calls to prevent hoisting, and report the median sample.
 * Cycles are full 64-bit rdtsc counts; CPB = median / (NRUNS * msg_len).
 *
 * - HCTR++:      this repository (include/hctrpp.h), 16-byte tweak
 * - BBB-DDD-AES: Intel reference, performance variant (vendor/), 12-byte
 *                tweak (fixed by that implementation), zeroization disabled
 * - PHCTR+:      linked from ../HCTR_PLUS (Deoxys-BC based), 16-byte tweak
 *
 * MIT license.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <x86intrin.h>

#include "include/hctrpp.h"
#include "vendor/bbb-ddd-aes-perf/bbb-ddd-aes-ref-perf.h"
/* HCTR_PLUS prototypes last: its headers redefine `inline`/`restrict` */
#include "init.h"

#define WARM 1024
#define NRUNS 128
#define NSAMP 16

static uint64_t samples[NSAMP];

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

#define MEASURE(expr, out_med) do {                                       \
        for (int s_ = 0; s_ < NSAMP; s_++) {                              \
            for (int w_ = 0; w_ < WARM; w_++) { expr; }                   \
            uint64_t c_ = __rdtsc();                                      \
            for (int r_ = 0; r_ < NRUNS; r_++) { expr; }                  \
            samples[s_] = __rdtsc() - c_;                                 \
        }                                                                 \
        qsort(samples, NSAMP, sizeof samples[0], cmp_u64);                \
        out_med = (double)samples[NSAMP / 2];                             \
    } while (0)

#define MAXLEN 65536

static uint8_t ALIGN128 pt[MAXLEN];
static uint8_t ALIGN128 ct[MAXLEN];
static uint8_t ALIGN128 dt[MAXLEN];

int main(void)
{
    uint8_t key[48], twk[16];
    size_t sizes[] = { 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 };
    size_t nsizes = sizeof(sizes) / sizeof(sizes[0]);
    double med;

    srand(0x5eed);
    for (size_t i = 0; i < sizeof(key); i++) key[i] = (uint8_t)rand();
    for (size_t i = 0; i < sizeof(twk); i++) twk[i] = (uint8_t)rand();
    for (size_t i = 0; i < MAXLEN; i++) pt[i] = (uint8_t)rand();

    /* ---- setup + correctness sanity for all three ---- */
    hctrpp_ctx hpp;
    hctrpp_init(&hpp, key);
    hctrpp_encrypt(&hpp, pt, 4096, twk, 16, ct);
    hctrpp_decrypt(&hpp, ct, 4096, twk, 16, dt);
    int ok_hpp = memcmp(pt, dt, 4096) == 0 && memcmp(pt, ct, 4096) != 0;

    static uint8_t ddd_ek[CRYPTO_EXPANDED_KEYBYTES];
    precompute_key(key, ddd_ek);
    bbb_ddd_aes_ref_perf_encrypt(ct, pt, 4096, ddd_ek, twk, TWEAKSIZE_BYTES);
    bbb_ddd_aes_ref_perf_decrypt(dt, ct, 4096, ddd_ek, twk, TWEAKSIZE_BYTES);
    int ok_ddd = memcmp(pt, dt, 4096) == 0 && memcmp(pt, ct, 4096) != 0;

    prp_ctx *hp = prp_allocate(NULL);
    prp_init(hp, key);
    prp_encrypt(hp, pt, 4096, twk, 16, ct, 1);
    prp_encrypt(hp, ct, 4096, twk, 16, dt, 0);
    int ok_hplus = memcmp(pt, dt, 4096) == 0 && memcmp(pt, ct, 4096) != 0;

    printf("round-trip sanity: HCTR++ %s, BBB-DDD-AES %s, PHCTR+ %s\n",
           ok_hpp ? "OK" : "FAIL", ok_ddd ? "OK" : "FAIL",
           ok_hplus ? "OK" : "FAIL");
    if (!ok_hpp || !ok_ddd || !ok_hplus)
        return 1;

    /* ---- key/context setup cost ---- */
    MEASURE((hctrpp_init(&hpp, key), key[1] ^= ((uint8_t *)&hpp)[9]), med);
    double setup_hpp = med / NRUNS;
    MEASURE((precompute_key(key, ddd_ek), key[1] ^= ddd_ek[9]), med);
    double setup_ddd = med / NRUNS;
    MEASURE((prp_init(hp, key), key[1] ^= ((uint8_t *)hp)[9]), med);
    double setup_hplus = med / NRUNS;
    printf("\nkey setup cycles: HCTR++ %.0f, BBB-DDD-AES %.0f, PHCTR+ %.0f\n\n",
           setup_hpp, setup_ddd, setup_hplus);
    hctrpp_init(&hpp, key);
    precompute_key(key, ddd_ek);
    prp_init(hp, key);

    /* ---- encryption cycles per byte ----
     * Three full passes over (size x cipher); per cell keep the best
     * (minimum) of the per-pass medians, which suppresses transient
     * scheduler/frequency interference between measurements. */
    static double cpb[8][3];
    for (size_t s = 0; s < nsizes; s++)
        cpb[s][0] = cpb[s][1] = cpb[s][2] = 1e30;
    for (int pass = 0; pass < 3; pass++) {
        for (size_t s = 0; s < nsizes; s++) {
            size_t len = sizes[s];
            double c;

            MEASURE((hctrpp_encrypt(&hpp, pt, len, twk, 16, ct),
                     pt[0] = ct[0]), med);
            c = med / ((double)NRUNS * (double)len);
            if (c < cpb[s][0]) cpb[s][0] = c;

            MEASURE((bbb_ddd_aes_ref_perf_encrypt(ct, pt, (uint32_t)len,
                                                  ddd_ek, twk,
                                                  TWEAKSIZE_BYTES),
                     pt[0] = ct[0]), med);
            c = med / ((double)NRUNS * (double)len);
            if (c < cpb[s][1]) cpb[s][1] = c;

            MEASURE((prp_encrypt(hp, pt, len, twk, 16, ct, 1),
                     pt[0] = ct[0]), med);
            c = med / ((double)NRUNS * (double)len);
            if (c < cpb[s][2]) cpb[s][2] = c;
        }
    }
    printf("| Message bytes | HCTR++ | BBB-DDD-AES | PHCTR+ |\n");
    printf("|--------------:|-------:|------------:|-------:|\n");
    for (size_t s = 0; s < nsizes; s++)
        printf("| %13zu | %6.2f | %11.2f | %6.2f |\n",
               sizes[s], cpb[s][0], cpb[s][1], cpb[s][2]);
    prp_free(hp);
    return 0;
}
