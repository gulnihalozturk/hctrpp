/*
 * Win64 entry points for the SysV-ABI Linux-kernel assembly that
 * ../CHCTR-HCTR2TwKD uses for AES-NI, XCTR and POLYVAL.
 *
 * On Windows the Makefile assembles those sources with each entry point
 * renamed to sysv_<name>.  The wrappers below keep the original names under
 * the Microsoft x64 ABI; GCC's sysv_abi call sequence moves the arguments
 * into the SysV registers and preserves rsi, rdi and xmm6-xmm15, which
 * Windows treats as callee-saved but the assembly clobbers.  Not built on
 * Linux, where the assembly is linked directly.
 *
 * MIT license.
 */
#include "aes_linux.h"
#include "polyval.h"

#define SYSV __attribute__((sysv_abi))

SYSV void sysv_clmul_polyval_update(const struct polyval_key *key,
                                    const u8 *in, size_t nblocks,
                                    u8 *accumulator);
SYSV void sysv_clmul_polyval_mul(u8 *op1, const u8 *op2);
SYSV void sysv_aesni_ecb_enc(const struct crypto_aes_ctx *ctx, u8 *dst,
                             const u8 *src, size_t len);
SYSV void sysv_aesni_ecb_dec(const struct crypto_aes_ctx *ctx, u8 *dst,
                             const u8 *src, size_t len);
SYSV void sysv_aes_xctr_enc_128_avx_by8(const u8 *in, const u8 *iv,
                                        const void *keys, u8 *out,
                                        unsigned int num_bytes,
                                        unsigned int byte_ctr);
SYSV void sysv_aes_xctr_enc_192_avx_by8(const u8 *in, const u8 *iv,
                                        const void *keys, u8 *out,
                                        unsigned int num_bytes,
                                        unsigned int byte_ctr);
SYSV void sysv_aes_xctr_enc_256_avx_by8(const u8 *in, const u8 *iv,
                                        const void *keys, u8 *out,
                                        unsigned int num_bytes,
                                        unsigned int byte_ctr);

/* Callers in polyval.c / polyval_xor.c / xctr.c declare these locally */
void clmul_polyval_update(const struct polyval_key *key, const u8 *in,
                          size_t nblocks, u8 *accumulator);
void clmul_polyval_mul(u8 *op1, const u8 *op2);
void aes_xctr_enc_128_avx_by8(const u8 *in, const u8 *iv, const void *keys,
                              u8 *out, unsigned int num_bytes,
                              unsigned int byte_ctr);
void aes_xctr_enc_192_avx_by8(const u8 *in, const u8 *iv, const void *keys,
                              u8 *out, unsigned int num_bytes,
                              unsigned int byte_ctr);
void aes_xctr_enc_256_avx_by8(const u8 *in, const u8 *iv, const void *keys,
                              u8 *out, unsigned int num_bytes,
                              unsigned int byte_ctr);

void clmul_polyval_update(const struct polyval_key *key, const u8 *in,
                          size_t nblocks, u8 *accumulator)
{
    sysv_clmul_polyval_update(key, in, nblocks, accumulator);
}

void clmul_polyval_mul(u8 *op1, const u8 *op2)
{
    sysv_clmul_polyval_mul(op1, op2);
}

void aesni_ecb_enc(const struct crypto_aes_ctx *ctx, u8 *dst, const u8 *src,
                   size_t len)
{
    sysv_aesni_ecb_enc(ctx, dst, src, len);
}

void aesni_ecb_dec(const struct crypto_aes_ctx *ctx, u8 *dst, const u8 *src,
                   size_t len)
{
    sysv_aesni_ecb_dec(ctx, dst, src, len);
}

void aes_xctr_enc_128_avx_by8(const u8 *in, const u8 *iv, const void *keys,
                              u8 *out, unsigned int num_bytes,
                              unsigned int byte_ctr)
{
    sysv_aes_xctr_enc_128_avx_by8(in, iv, keys, out, num_bytes, byte_ctr);
}

void aes_xctr_enc_192_avx_by8(const u8 *in, const u8 *iv, const void *keys,
                              u8 *out, unsigned int num_bytes,
                              unsigned int byte_ctr)
{
    sysv_aes_xctr_enc_192_avx_by8(in, iv, keys, out, num_bytes, byte_ctr);
}

void aes_xctr_enc_256_avx_by8(const u8 *in, const u8 *iv, const void *keys,
                              u8 *out, unsigned int num_bytes,
                              unsigned int byte_ctr)
{
    sysv_aes_xctr_enc_256_avx_by8(in, iv, keys, out, num_bytes, byte_ctr);
}
