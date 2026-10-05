/*
 * BBB accordion-mode benchmark: HCTR++ vs BBB-DDD-AES vs PHCTR+ (HCTR+ with
 * PHash) vs CHCTR2 vs HCTR2-TwKD.
 *
 * Methodology follows the HCTR_PLUS benchmark (Ghosh): for each data point,
 * take NSAMP=16 samples, each sample timing NRUNS=128 consecutive calls
 * after WARM=1024 cache-warming calls, feed one output byte back into the
 * input between calls to prevent hoisting, and report the median sample.
 * Cycles are full 64-bit rdtsc counts; CPB = median / (NRUNS * msg_len).
 * Samples taken while the core's SMT sibling was busy are retaken (see
 * smt_sibling_idle).
 *
 * - HCTR++:      this repository (include/hctrpp.h), 16-byte tweak
 * - BBB-DDD-AES: Intel reference, performance variant (vendor/), 12-byte
 *                tweak (fixed by that implementation), zeroization disabled
 * - PHCTR+:      linked from ../HCTR_PLUS (Deoxys-BC based), 16-byte tweak
 * - CHCTR2, HCTR2-TwKD: linked from ../CHCTR-HCTR2TwKD (ePrint 2026/085)
 *                through bench/chctr_glue.h, 16-byte tweak (126-bit for
 *                TwKD), each with AES-128 (key-size-matched variant) and
 *                AES-256 (as specified)
 *
 * MIT license.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <x86intrin.h>

#include "include/hctrpp.h"
#include "bench/chctr_glue.h"
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

/* SMT guard.  Another process running on the measuring core's sibling
 * hyperthread slows store-heavy code by up to ~1.6x (BBB-DDD-AES at 512
 * bytes: 2.0 -> 3.3 cpb) without taking cycles from this thread, and such
 * phases last seconds, so neither the median nor the best-of-passes
 * rejects them.  A 4 KiB store burst runs about 2x slower in that state.
 * Each sample starts once the burst runs within 25% of its fastest
 * observed time and is retaken (up to SMT_RETRIES times) if it no longer
 * does when the sample ends.  Waits are bounded; a sibling that stays busy
 * through SMT_GIVEUP consecutive waits switches the guard off.  The
 * reference is relative, so a sibling that is busy for the whole run
 * (including calibration) goes undetected; the printed baseline then reads
 * about twice its idle value. */
#define SMT_RETRIES 8
#define SMT_WAIT_TICKS (1ull << 31)   /* ~0.5 s at 4-5 GHz */
#define SMT_GIVEUP 8

static uint8_t ALIGN128 smt_buf[4096];
static uint64_t smt_idle_ticks = UINT64_MAX;
static unsigned long smt_retakes, smt_timeouts;
static int smt_guard = 1;

static void spin_ticks(uint64_t n)
{
    for (uint64_t t = __rdtsc(); __rdtsc() - t < n;)
        _mm_pause();
}

static int smt_sibling_idle(void)
{
    uint64_t best = UINT64_MAX;
    for (int i = 0; i < 32; i++) {
        uint64_t t = __rdtsc();
        memset(smt_buf, i, sizeof smt_buf);
        __asm__ volatile("" : : "r"(smt_buf) : "memory");
        t = __rdtsc() - t;
        if (t < best) best = t;
    }
    if (best < smt_idle_ticks)
        smt_idle_ticks = best;
    return best * 4 <= smt_idle_ticks * 5;
}

/* Spread the baseline over ~1 s so it sees an idle-sibling moment */
static void smt_calibrate(void)
{
    for (int i = 0; i < 1000; i++) {
        smt_sibling_idle();
        spin_ticks(5000000);
    }
}

static void smt_wait_idle(void)
{
    static int consecutive;
    uint64_t t0 = __rdtsc();

    while (smt_guard && !smt_sibling_idle()) {
        if (__rdtsc() - t0 > SMT_WAIT_TICKS) {
            smt_timeouts++;
            if (++consecutive == SMT_GIVEUP)
                smt_guard = 0;
            return;
        }
        spin_ticks(200000);
    }
    consecutive = 0;
}

#define MEASURE(expr, out_med) do {                                       \
        for (int s_ = 0; s_ < NSAMP; s_++) {                              \
            for (int t_ = 0;; t_++) {                                     \
                smt_wait_idle();                                          \
                for (int w_ = 0; w_ < WARM; w_++) { expr; }               \
                uint64_t c_ = __rdtsc();                                  \
                for (int r_ = 0; r_ < NRUNS; r_++) { expr; }              \
                samples[s_] = __rdtsc() - c_;                             \
                if (!smt_guard || t_ == SMT_RETRIES || smt_sibling_idle())\
                    break;                                                \
                smt_retakes++;                                            \
            }                                                             \
        }                                                                 \
        qsort(samples, NSAMP, sizeof samples[0], cmp_u64);                \
        out_med = (double)samples[NSAMP / 2];                             \
    } while (0)

#define MAXLEN 65536

static uint8_t ALIGN128 pt[MAXLEN];
static uint8_t ALIGN128 ct[MAXLEN];
static uint8_t ALIGN128 dt[MAXLEN];

enum { HPP, DDD, HPLUS, CH128, CH256, TW128, TW256, NCIPHERS };
static const char *names[NCIPHERS] = {
    "HCTR++", "BBB-DDD-AES", "PHCTR+", "CHCTR2-128", "CHCTR2-256",
    "TwKD-128", "TwKD-256",
};

static int round_trip_ok(void)
{
    return memcmp(pt, dt, 4096) == 0 && memcmp(pt, ct, 4096) != 0;
}

int main(void)
{
    uint8_t key[64], twk[16];
    size_t sizes[] = { 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 };
    size_t nsizes = sizeof(sizes) / sizeof(sizes[0]);
    double med;
    int ok[NCIPHERS];

    srand(0x5eed);
    for (size_t i = 0; i < sizeof(key); i++) key[i] = (uint8_t)rand();
    for (size_t i = 0; i < sizeof(twk); i++) twk[i] = (uint8_t)rand();
    for (size_t i = 0; i < MAXLEN; i++) pt[i] = (uint8_t)rand();
    /* HCTR2-TwKD takes a 126-bit tweak: the top two bits of byte 0 carry
     * its KDF prefix and must be zero.  Shared by all ciphers. */
    twk[0] &= 0x3f;

    /* ---- setup + correctness sanity for all ciphers ---- */
    if (bench_chctr_selftest() != 0)
        return 1;

    hctrpp_ctx hpp;
    hctrpp_init(&hpp, key);
    hctrpp_encrypt(&hpp, pt, 4096, twk, 16, ct);
    hctrpp_decrypt(&hpp, ct, 4096, twk, 16, dt);
    ok[HPP] = round_trip_ok();

    static uint8_t ddd_ek[CRYPTO_EXPANDED_KEYBYTES];
    precompute_key(key, ddd_ek);
    bbb_ddd_aes_ref_perf_encrypt(ct, pt, 4096, ddd_ek, twk, TWEAKSIZE_BYTES);
    bbb_ddd_aes_ref_perf_decrypt(dt, ct, 4096, ddd_ek, twk, TWEAKSIZE_BYTES);
    ok[DDD] = round_trip_ok();

    prp_ctx *hp = prp_allocate(NULL);
    prp_init(hp, key);
    prp_encrypt(hp, pt, 4096, twk, 16, ct, 1);
    prp_encrypt(hp, ct, 4096, twk, 16, dt, 0);
    ok[HPLUS] = round_trip_ok();

    bench_chctr2 *ch128 = bench_chctr2_new(), *ch256 = bench_chctr2_new();
    bench_chctr2_setkey(ch128, key, 16);
    bench_chctr2_setkey(ch256, key, 32);
    bench_chctr2_encrypt(ch128, pt, 4096, twk, 16, ct);
    bench_chctr2_decrypt(ch128, ct, 4096, twk, 16, dt);
    ok[CH128] = round_trip_ok();
    bench_chctr2_encrypt(ch256, pt, 4096, twk, 16, ct);
    bench_chctr2_decrypt(ch256, ct, 4096, twk, 16, dt);
    ok[CH256] = round_trip_ok();

    bench_twkd *tw128 = bench_twkd_new(), *tw256 = bench_twkd_new();
    bench_twkd_setkey(tw128, key, 16);
    bench_twkd_setkey(tw256, key, 32);
    bench_twkd_encrypt(tw128, pt, 4096, twk, ct);
    bench_twkd_decrypt(tw128, ct, 4096, twk, dt);
    ok[TW128] = round_trip_ok();
    bench_twkd_encrypt(tw256, pt, 4096, twk, ct);
    bench_twkd_decrypt(tw256, ct, 4096, twk, dt);
    ok[TW256] = round_trip_ok();

    int all_ok = 1;
    printf("round-trip sanity:");
    for (int c = 0; c < NCIPHERS; c++) {
        printf("%s %s %s", c ? "," : "", names[c], ok[c] ? "OK" : "FAIL");
        all_ok &= ok[c];
    }
    printf("\n");
    if (!all_ok)
        return 1;

    /* ---- key/context setup cost ----
     * HCTR2-TwKD's setup is the KDF key schedule only; it derives and
     * schedules the HCTR2 key per message, inside the encryption timing. */
    double setup[NCIPHERS];
    smt_calibrate();
    MEASURE((hctrpp_init(&hpp, key), key[1] ^= ((uint8_t *)&hpp)[9]), med);
    setup[HPP] = med / NRUNS;
    MEASURE((precompute_key(key, ddd_ek), key[1] ^= ddd_ek[9]), med);
    setup[DDD] = med / NRUNS;
    MEASURE((prp_init(hp, key), key[1] ^= ((uint8_t *)hp)[9]), med);
    setup[HPLUS] = med / NRUNS;
    MEASURE((bench_chctr2_setkey(ch128, key, 16),
             key[1] ^= ((uint8_t *)ch128)[9]), med);
    setup[CH128] = med / NRUNS;
    MEASURE((bench_chctr2_setkey(ch256, key, 32),
             key[1] ^= ((uint8_t *)ch256)[9]), med);
    setup[CH256] = med / NRUNS;
    MEASURE((bench_twkd_setkey(tw128, key, 16),
             key[1] ^= ((uint8_t *)tw128)[9]), med);
    setup[TW128] = med / NRUNS;
    MEASURE((bench_twkd_setkey(tw256, key, 32),
             key[1] ^= ((uint8_t *)tw256)[9]), med);
    setup[TW256] = med / NRUNS;
    printf("\nkey setup cycles:");
    for (int c = 0; c < NCIPHERS; c++)
        printf("%s %s %.0f", c ? "," : "", names[c], setup[c]);
    printf("\n\n");
    hctrpp_init(&hpp, key);
    precompute_key(key, ddd_ek);
    prp_init(hp, key);
    bench_chctr2_setkey(ch128, key, 16);
    bench_chctr2_setkey(ch256, key, 32);
    bench_twkd_setkey(tw128, key, 16);
    bench_twkd_setkey(tw256, key, 32);

    /* ---- encryption cycles per byte ----
     * Three full passes over (size x cipher); per cell keep the best
     * (minimum) of the per-pass medians, which suppresses transient
     * scheduler/frequency interference between measurements. */
    static double cpb[8][NCIPHERS];
    for (size_t s = 0; s < nsizes; s++)
        for (int c = 0; c < NCIPHERS; c++)
            cpb[s][c] = 1e30;
#define CELL(c, call) do {                                                \
        MEASURE((call, pt[0] = ct[0]), med);                              \
        double v_ = med / ((double)NRUNS * (double)len);                  \
        if (v_ < cpb[s][c]) cpb[s][c] = v_;                               \
    } while (0)
    for (int pass = 0; pass < 3; pass++) {
        for (size_t s = 0; s < nsizes; s++) {
            size_t len = sizes[s];

            CELL(HPP, hctrpp_encrypt(&hpp, pt, len, twk, 16, ct));
            CELL(DDD, bbb_ddd_aes_ref_perf_encrypt(ct, pt, (uint32_t)len,
                                                   ddd_ek, twk,
                                                   TWEAKSIZE_BYTES));
            CELL(HPLUS, prp_encrypt(hp, pt, len, twk, 16, ct, 1));
            CELL(CH128, bench_chctr2_encrypt(ch128, pt, len, twk, 16, ct));
            CELL(CH256, bench_chctr2_encrypt(ch256, pt, len, twk, 16, ct));
            CELL(TW128, bench_twkd_encrypt(tw128, pt, len, twk, ct));
            CELL(TW256, bench_twkd_encrypt(tw256, pt, len, twk, ct));
        }
    }
#undef CELL

    printf("| Message bytes |");
    for (int c = 0; c < NCIPHERS; c++)
        printf(" %s |", names[c]);
    printf("\n|--------------:|");
    for (int c = 0; c < NCIPHERS; c++) {
        for (size_t i = 0; i < strlen(names[c]) + 1; i++)
            putchar('-');
        printf(":|");
    }
    printf("\n");
    for (size_t s = 0; s < nsizes; s++) {
        printf("| %13zu |", sizes[s]);
        for (int c = 0; c < NCIPHERS; c++)
            printf(" %*.2f |", (int)strlen(names[c]), cpb[s][c]);
        printf("\n");
    }
    printf("\nSMT guard: %lu samples retaken, %lu waits timed out "
           "(store-burst baseline %llu ticks)\n",
           smt_retakes, smt_timeouts, (unsigned long long)smt_idle_ticks);
    if (!smt_guard)
        printf("WARNING: the SMT sibling stayed busy and the guard was "
               "switched off; results are unreliable\n");
    prp_free(hp);
    bench_chctr2_free(ch128);
    bench_chctr2_free(ch256);
    bench_twkd_free(tw128);
    bench_twkd_free(tw256);
    return 0;
}
