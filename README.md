# HCTR++ reference implementation

Implementation of **HCTR++**, the beyond-birthday-bound secure HCTR2 variant
specified in *"HCTR++: A Beyond Birthday Bound Secure HCTR2 Variant"*
(Öztürk, Koçak, Yayla — ePrint 2026/383), Figure 4, instantiated with
AES-128 (n = 128).

Two mutually validating implementations:

* `python/hctrpp.py` — executable specification (readability, test-vector
  generation)
* `src/hctrpp.c` + `include/hctrpp.h` — optimized C (AES-NI + PCLMULQDQ,
  with an AVX-512 VAES/VPCLMULQDQ fast path when available)

## Instantiation details fixed by this implementation

The paper leaves the concrete 2n-bit hash open ("for instance POLYVAL over
GF(2^256)"). This implementation defines the normative instantiation,
mirroring the HCTR2 reference conventions (ePrint 2021/1441):

* **POLYVAL256** — the RFC 8452 POLYVAL construction lifted to GF(2²⁵⁶),
  using `P(x) = x^256 + x^254 + x^251 + x^246 + 1`, the reciprocal of
  `x^256 + x^10 + x^5 + x^2 + 1` — the lexicographically-first minimum-weight
  irreducible polynomial of degree 256, i.e., the natural GHASH-style choice
  for a 256-bit field. Field elements are 256-bit strings in little-endian order
  (bit *i* of the string is the coefficient of `x^i`).
  `POLYVAL256(h, M_1..M_l): S_j = (S_{j-1} xor M_j) * h * x^-256`, `S_0 = 0`.
* **Hash input encoding** `H_h(T, M)` — HCTR2's encoding with 32-byte blocks:
  `bin256(2|T| + 2 [+1 if |M| mod 256 != 0]) || pad(T) || (M | pad(M || 0x01))`
  with `|T|` the tweak length in bits, `bin256`/`pad` little-endian /
  zero-padding to 32 bytes.
* **Re-keying hash** — `H_Kbar(r)` is the same `H` with empty tweak and
  message `r` (16 bytes).
* **Subkeys** — `h1 = E_K(bin(1)) || E_K(bin(2))`,
  `h2 = E_K(bin(3)) || E_K(bin(4))`, `Kbar = E_K(bin(5)) || E_K(bin(6))`,
  `bin(i)` the 16-byte little-endian encoding.
* **Counters** — `J_i = J xor bin128(i)`, `r_i = r xor bin128(i)`,
  `i = 1..m` (XCTR convention).
* **Halves** — for a 2n-bit string `s`, `MSB_n(s)` is the leading 16 bytes,
  `LSB_n(s)` the trailing 16 bytes; in hash outputs `u||v` and `r||J`, the
  first-named half is the leading one.

Messages are byte strings of length >= 16; tweaks are arbitrary byte
strings. Decryption is encryption with the roles of `h1`/`h2` swapped
(the structural symmetry from the paper).

## Build and validate

Requires x86-64 with AES-NI + PCLMULQDQ (AVX-512 VAES used when the CPU has
it), gcc, and Python 3 with `pycryptodomex` for the specification.

```
python python/hctrpp.py                       # spec self-test
make kat                                      # regenerate testvectors/ from spec
make hctrpp_validation && ./hctrpp_validation # C vs spec: KATs + round-trips
```

`hctrpp_validation` checks POLYVAL256 unit vectors, 18 Python-generated mode
KATs (encrypt / decrypt / in-place), and 145 round-trips over odd message
and tweak lengths.

## Benchmark: HCTR++ vs BBB-DDD-AES vs HCTR+

`benchmark3.c` measures the three BBB accordion-mode candidates in one
binary, one methodology:

* **HCTR++** — this repository (16-byte tweak)
* **BBB-DDD-AES** — Intel's reference, *performance* variant
  (`vendor/bbb-ddd-aes-perf/`, MIT), 12-byte tweak as fixed by that code,
  zeroization disabled; two small benchmark patches are marked with
  `[benchmark patch]` comments
* **PHCTR+** — HCTR+ with PHash, linked directly from the authors'
  `../HCTR_PLUS` checkout (Deoxys-BC-128-256 based), 16-byte tweak

Methodology (after the HCTR_PLUS benchmark): per data point, 16 samples,
each timing 128 consecutive encryptions after 1024 cache-warming calls with
one output byte fed back into the input; the median sample is taken, and the
best median of three full passes is reported. Cycles are `rdtsc` counts;
CPB = cycles / message bytes. Key/context setup is excluded (done once) and
reported separately.

```
make benchmark3 && ./benchmark3
```

### Results

AMD Ryzen 7 9800X3D (Zen 5), gcc 15.2.0 (MSYS2), `-O3 -march=native`,
Windows 11. `rdtsc` ticks at base clock; cores boost above it, identically
for all three ciphers.

Encryption, cycles per byte:

| Message bytes | HCTR++ | BBB-DDD-AES | PHCTR+ |
|--------------:|-------:|------------:|-------:|
|           512 |   3.72 |        1.97 |   1.77 |
|          1024 |   2.75 |        1.78 |   1.31 |
|          2048 |   2.26 |        1.76 |   1.07 |
|          4096 |   2.02 |        1.66 |   0.96 |
|          8192 |   1.90 |        1.54 |   0.90 |
|         16384 |   1.85 |        1.48 |   0.88 |
|         32768 |   1.82 |        1.44 |   0.87 |
|         65536 |   1.80 |        1.44 |   0.85 |

Key/context setup: HCTR++ 373 cycles, BBB-DDD-AES 153, PHCTR+ 806.

Notes:

* HCTR++ pays one fresh AES-128 key schedule **plus** one GF(2^256)
  multiplication per 16-byte block (the R3 re-keying), yet lands within
  ~25% of BBB-DDD-AES at large messages. The VAES path computes the
  re-keying hash, key schedule, and AES for four blocks lane-parallel in
  zmm registers; message hashing uses 4-block aggregated POLYVAL256 with
  precomputed key powers. The field multiply is a POLYVAL-style Montgomery
  product `a*b*x^-256`: with the reciprocal polynomial, `1 = x^256 + C*x^192`
  for a 64-bit constant `C`, so the reduction is four CLMULs by `C` on top
  of the 12 for the 256x256 product, and no `x^-256` key premultiplication
  is needed.
* HCTR++ and BBB-DDD-AES numbers are stable to +-0.01 cpb across runs and
  builds. PHCTR+ is sensitive to code layout: builds of byte-identical
  object code (different link order, or unrelated changes elsewhere in the
  binary) measure between 0.85 and 1.12 cpb at 64 KiB. The PHCTR+ column
  reports its best observed placement; the build as committed measures
  0.90-0.94 cpb at 64 KiB.
* PHCTR+ reaches TBC speed with Deoxys-BC, a non-standard primitive;
  HCTR++ and BBB-DDD-AES use plain AES-128. Security: HCTR++ O(2^n) (tweak-
  reuse dependent), BBB-DDD-AES O(2^{2n/3}), HCTR+ O(2^n) (paper, Table 1).
* All three schemes are structurally symmetric; decryption performance
  matches encryption.

## Licenses

This implementation: MIT. `vendor/bbb-ddd-aes-perf/` is Intel's MIT-licensed
code with marked benchmark patches. HCTR_PLUS sources are linked from the
sibling checkout, not copied.
