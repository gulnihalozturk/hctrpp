#!/usr/bin/env python3
# HCTR++ reference implementation (executable specification).
#
# Implements HCTR++ as specified in "HCTR++: A Beyond Birthday Bound Secure
# HCTR2 Variant" (Ozturk, Kocak, Yayla, ePrint 2026/383), Figure 4.
#
# Details the paper leaves open are fixed here, mirroring the HCTR2
# reference conventions (Crowley-Huckleberry-Biggers, ePrint 2021/1441):
#
#   * n = 128 (AES-128); the 2n-bit AXU hash is POLYVAL256: the RFC 8452
#     POLYVAL construction lifted to GF(2^256) with the reciprocal of the
#     Rijndael-256/GHASH-256 field polynomial, P(x) = x^256 + x^254 + x^251
#     + x^246 + 1 (irreducible, being the reversal of x^256+x^10+x^5+x^2+1).
#     Field elements are 256-bit strings, little-endian (bit i <-> x^i).
#     POLYVAL256(h, M1..Ml): S_j = (S_{j-1} xor M_j) * h * x^-256, S_0 = 0.
#   * H_h(T, M) uses the HCTR2 input encoding with 32-byte blocks:
#     bin256(2*|T| + 2 [+1 if |M| % 256 != 0]) || pad(T) || (M | pad(M || 0x01))
#     where |T| is the tweak length in bits and pad() zero-pads to 32 bytes.
#   * The re-keying hash H_Kbar(r) is H_Kbar(T=empty, M=r) with the same H.
#   * bin128(i) is the 16-byte little-endian encoding of i; block counters
#     enter via XOR (J_i = J xor bin128(i), r_i = r xor bin128(i)), as in XCTR.
#   * For a 2n-bit string s, MSB_n(s) = s[0:16] and LSB_n(s) = s[16:32]
#     (leading half / trailing half), matching P1 = MSB_n(P).
#
# Requires: pycryptodomex (Cryptodome.Cipher.AES).

import sys
from Cryptodome.Cipher import AES

BLOCK = 16    # n/8
HBLOCK = 32   # 2n/8

# ---------------------------------------------------------------- GF(2^256)

_POLY = (1 << 256) | (1 << 254) | (1 << 251) | (1 << 246) | 1
_MASK = (1 << 256) - 1


def _gf_mul(a, b):
    """Carry-less multiply then reduce mod P(x)."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        b >>= 1
    # x^256 == x^254 + x^251 + x^246 + 1 (mod P)
    while r >> 256:
        hi = r >> 256
        r = (r & _MASK) ^ hi ^ (hi << 246) ^ (hi << 251) ^ (hi << 254)
    return r


def _gf_sq(a):
    return _gf_mul(a, a)


# x^-1 = x^255 + x^253 + x^250 + x^245;  x^-256 = (x^-1)^(2^8) via 8 squarings
_XINV = (1 << 255) | (1 << 253) | (1 << 250) | (1 << 245)
_XINV256 = _XINV
for _ in range(8):
    _XINV256 = _gf_sq(_XINV256)


def polyval256(key, message):
    """POLYVAL over GF(2^256). key, message are bytes; len(message) % 32 == 0."""
    assert len(key) == HBLOCK and len(message) % HBLOCK == 0
    hpoly = _gf_mul(int.from_bytes(key, 'little'), _XINV256)
    s = 0
    for i in range(0, len(message), HBLOCK):
        s = _gf_mul(s ^ int.from_bytes(message[i:i + HBLOCK], 'little'), hpoly)
    return s.to_bytes(HBLOCK, 'little')


# ------------------------------------------------------------------- hash H

def _pad(s):
    return s + b'\x00' * ((-len(s)) % HBLOCK)


def hash_t(hkey, tweak, message):
    """H_hkey(T=tweak, M=message) -> 32 bytes (HCTR2 encoding, 32-byte blocks)."""
    awkward = len(message) % HBLOCK != 0
    lengthint = len(tweak) * 8 * 2 + 2 + (1 if awkward else 0)
    blocks = lengthint.to_bytes(HBLOCK, 'little') + _pad(tweak)
    blocks += _pad(message + b'\x01') if awkward else message
    return polyval256(hkey, blocks)


# ------------------------------------------------------------------- HCTR++

def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _bin128(i):
    return i.to_bytes(BLOCK, 'little')


def _derive(key):
    e = AES.new(key, AES.MODE_ECB)
    blk = [e.encrypt(_bin128(i)) for i in range(1, 7)]
    h1 = blk[0] + blk[1]
    h2 = blk[2] + blk[3]
    kbar = blk[4] + blk[5]
    return h1, h2, kbar


def _rekey_block(kbar, r, x, inverse=False):
    """R3 re-keying: u||v = H_Kbar(r); E_u(x xor v) xor v (or D_u for inverse)."""
    uv = hash_t(kbar, b'', r)
    u, v = uv[:BLOCK], uv[BLOCK:]
    aes = AES.new(u, AES.MODE_ECB)
    core = aes.decrypt if inverse else aes.encrypt
    return _xor(core(_xor(x, v)), v)


def _crypt(key, tweak, data, decrypt=False):
    assert len(key) == BLOCK and len(data) >= BLOCK
    h1, h2, kbar = _derive(key)
    ha, hb = (h2, h1) if decrypt else (h1, h2)
    h12 = _xor(h1, h2)

    b1, rest = data[:BLOCK], data[BLOCK:]

    x1 = hash_t(ha, tweak, rest)
    pp1 = _xor(b1, x1[:BLOCK])
    re = x1[BLOCK:]
    cc = _rekey_block(kbar, re, pp1)

    x = hash_t(h12, tweak, cc)
    r, j = x[:BLOCK], x[BLOCK:]

    m = (len(rest) + BLOCK - 1) // BLOCK
    ks = b''.join(
        _rekey_block(kbar, _xor(r, _bin128(i)), _xor(j, _bin128(i)))
        for i in range(1, m + 1))
    out_rest = _xor(rest, ks[:len(rest)])

    x2 = hash_t(hb, tweak, out_rest)
    rd = x2[BLOCK:]
    pp2 = _rekey_block(kbar, rd, cc, inverse=True)
    out1 = _xor(pp2, x2[:BLOCK])
    return out1 + out_rest


def encrypt(key, tweak, pt):
    return _crypt(key, tweak, pt, decrypt=False)


def decrypt(key, tweak, ct):
    return _crypt(key, tweak, ct, decrypt=True)


# ----------------------------------------------------------------- self test

def selftest():
    import hashlib

    def det(tag, n):  # deterministic pseudo-random bytes
        out = b''
        c = 0
        while len(out) < n:
            out += hashlib.sha256(tag.encode() + c.to_bytes(4, 'little')).digest()
            c += 1
        return out[:n]

    for klen in [16]:
        key = det('key', klen)
        for tlen in [0, 1, 16, 17, 32, 33, 47, 64]:
            for mlen in [16, 17, 31, 32, 33, 48, 63, 64, 65, 128, 255, 512]:
                t = det(f'twk{tlen}', tlen)
                p = det(f'msg{mlen}', mlen)
                c = encrypt(key, t, p)
                assert len(c) == len(p)
                assert decrypt(key, t, c) == p, (tlen, mlen)
                # a different tweak must change everything
                if tlen:
                    c2 = encrypt(key, det(f'twk{tlen}x', tlen), p)
                    assert c2 != c
    print("selftest OK")


# --------------------------------------------------------- test vector output

def _carr(b):
    return ','.join(f'0x{x:02x}' for x in b)


def gen_kat_header(path):
    import hashlib

    def det(tag, n):
        out = b''
        c = 0
        while len(out) < n:
            out += hashlib.sha256(tag.encode() + c.to_bytes(4, 'little')).digest()
            c += 1
        return out[:n]

    cases = []
    key = bytes(range(16))                      # 000102...0f
    for tlen, mlen in [(0, 16), (16, 16), (16, 17), (16, 31), (16, 32),
                       (16, 33), (16, 48), (16, 64), (16, 65), (16, 128),
                       (16, 255), (16, 512), (0, 48), (1, 48), (17, 48),
                       (32, 48), (33, 48), (64, 100)]:
        t = det(f'tweak-{tlen}-{mlen}', tlen)
        p = det(f'msg-{tlen}-{mlen}', mlen)
        cases.append((key, t, p, encrypt(key, t, p)))

    lines = [
        '/* Generated by python/hctrpp.py -- do not edit. */',
        '#include <stddef.h>',
        '#include <stdint.h>',
        'typedef struct {',
        '    const uint8_t *key;',
        '    const uint8_t *tweak; size_t tweak_len;',
        '    const uint8_t *pt; const uint8_t *ct; size_t msg_len;',
        '} hctrpp_kat_t;',
        '',
    ]
    for i, (k, t, p, c) in enumerate(cases):
        lines.append(f'static const uint8_t kat{i}_key[] = {{{_carr(k)}}};')
        lines.append(f'static const uint8_t kat{i}_twk[] = {{{_carr(t) if t else "0"}}};')
        lines.append(f'static const uint8_t kat{i}_pt[]  = {{{_carr(p)}}};')
        lines.append(f'static const uint8_t kat{i}_ct[]  = {{{_carr(c)}}};')
    lines.append('')
    lines.append('static const hctrpp_kat_t hctrpp_kats[] = {')
    for i, (k, t, p, c) in enumerate(cases):
        lines.append(f'    {{kat{i}_key, kat{i}_twk, {len(t)}, '
                     f'kat{i}_pt, kat{i}_ct, {len(p)}}},')
    lines.append('};')

    # POLYVAL256 unit vectors (for bisection)
    pv_key = det('pvkey', 32)
    lines.append('')
    for i, mlen in enumerate([32, 96]):
        msg = det(f'pvmsg{mlen}', mlen)
        dig = polyval256(pv_key, msg)
        lines.append(f'static const uint8_t pv{i}_msg[] = {{{_carr(msg)}}};')
        lines.append(f'static const uint8_t pv{i}_dig[] = {{{_carr(dig)}}};')
    lines.append(f'static const uint8_t pv_key[] = {{{_carr(pv_key)}}};')
    lines.append('')

    with open(path, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    print(f'wrote {path} ({len(cases)} mode vectors)')


if __name__ == '__main__':
    selftest()
    if len(sys.argv) > 1:
        gen_kat_header(sys.argv[1])
