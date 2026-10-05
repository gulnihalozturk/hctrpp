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

## Benchmark: HCTR++ vs BBB-DDD-AES vs HCTR+ vs CHCTR2 vs HCTR2-TwKD

`benchmark.c` measures five BBB accordion-mode candidates in one binary,
one methodology:

* **HCTR++** — this repository (16-byte tweak)
* **BBB-DDD-AES** — Intel's reference, *performance* variant
  (`vendor/bbb-ddd-aes-perf/`, MIT), 12-byte tweak as fixed by that code,
  zeroization disabled; two small benchmark patches are marked with
  `[benchmark patch]` comments
* **PHCTR+** — HCTR+ with PHash, linked directly from the authors'
  `../HCTR_PLUS` checkout (Deoxys-BC-128-256 based), 16-byte tweak
* **CHCTR2** and **HCTR2-TwKD** — Chen et al., ePrint 2026/085, compiled
  from the `../CHCTR-HCTR2TwKD` checkout through the adapter in `bench/`,
  each in two instantiations:
  * `-256`: AES-256 as the paper specifies, exactly the upstream code.
    CHCTR2 key `K1 || K2` (2 x 32 bytes), 16-byte tweak; TwKD 126-bit tweak
    (16 bytes, top two bits zero), KDF key `L` (32 bytes), per-message key
    `(E_L(00||T) ^ E_L(01||T)) || (E_L(00||T) ^ E_L(10||T))`.
  * `-128`: AES-128 variants, key-size-matched to HCTR++ and not part of the
    paper. CHCTR2 with two AES-128 keys; TwKD with an AES-128 `L` and the
    one-block CENC output `E_L(00||T) ^ E_L(01||T)` (the first half of the
    256-bit derivation) as the AES-128 HCTR2 key.

On MinGW, the upstream Linux-kernel assembly (SysV ABI, ELF) is built by
the Makefile as follows: it preprocesses the sources, rewrites the ELF-only
section directives for COFF, renames the entry points to `sysv_*`, and calls
them through GCC `sysv_abi` thunks (`bench/win64_sysv_thunks.c`). On Linux
the assembly links unchanged. Upstream's conformance suite cannot exercise
the accelerated paths on Windows, so the benchmark self-tests the build
before timing. It checks the 72 frozen upstream vectors (encrypt and decrypt)
through the accelerated path, and compares the accelerated path against
upstream's generic C path for both key sizes across 11 message lengths
(16 B to 64 KiB) and 5 tweak lengths. It also checks that CHCTR2 equals two
black-box HCTR2 calls, and that the TwKD-128 key equals the first half of
upstream's derivation.

Methodology (after the HCTR_PLUS benchmark): per data point, 16 samples,
each timing 128 consecutive encryptions after 1024 cache-warming calls with
one output byte fed back into the input; the median sample is taken, and the
best median of three full passes is reported. Cycles are `rdtsc` counts;
CPB = cycles / message bytes. Key/context setup is excluded (done once) and
reported separately.

SMT guard: another process scheduled on the measuring core's sibling
hyperthread slows store-heavy code by up to ~1.6x without taking cycles from
the benchmark thread (BBB-DDD-AES at 512 bytes: 2.0 -> 3.3 cpb). Such phases
last seconds, so neither the median nor the best of three passes rejects
them. A 4 KiB store burst runs about 2x slower in that state. Each sample
starts only once the burst runs within 25% of its fastest observed time, and
is retaken if it no longer does when the sample ends. The run reports how
many samples were retaken, plus the burst baseline: 47 ticks on the machine
below. The reference is relative, so a sibling that stays busy for the
entire run goes undetected, and the baseline then reads about 2x high. On a
loaded machine, idle the other cores or disable SMT.

```
make benchmark && ./benchmark
```

Needs the sibling checkouts `../HCTR_PLUS` and `../CHCTR-HCTR2TwKD`, and
Python 3 to convert the latter's frozen test vectors.

### Results

AMD Ryzen 7 9800X3D (Zen 5), gcc 15.2.0 (MSYS2), `-O3 -march=native`,
Windows 11. `rdtsc` ticks at base clock; cores boost above it, identically
for all ciphers.

Encryption, cycles per byte:

| Message bytes | HCTR++ | BBB-DDD-AES | PHCTR+ | CHCTR2-128 | CHCTR2-256 | TwKD-128 | TwKD-256 |
|--------------:|-------:|------------:|-------:|-----------:|-----------:|---------:|---------:|
|           512 |   3.73 |        1.99 |   1.78 |       2.36 |       2.64 |     2.86 |     3.36 |
|          1024 |   2.75 |        1.78 |   1.31 |       2.18 |       2.44 |     2.06 |     2.36 |
|          2048 |   2.27 |        1.76 |   1.08 |       2.09 |       2.33 |     1.65 |     1.87 |
|          4096 |   2.02 |        1.65 |   0.97 |       2.04 |       2.28 |     1.45 |     1.62 |
|          8192 |   1.90 |        1.53 |   0.91 |       2.03 |       2.27 |     1.36 |     1.49 |
|         16384 |   1.85 |        1.48 |   0.88 |       2.02 |       2.25 |     1.31 |     1.44 |
|         32768 |   1.82 |        1.45 |   0.87 |       2.03 |       2.28 |     1.29 |     1.41 |
|         65536 |   1.80 |        1.45 |   0.88 |       2.03 |       2.27 |     1.27 |     1.40 |

Key/context setup: HCTR++ 373 cycles, BBB-DDD-AES 153, PHCTR+ 762,
CHCTR2-128 148595, CHCTR2-256 149466, TwKD-128 220, TwKD-256 315.

All columns come from a single run. Three runs of this build agreed within
+-0.03 cpb in every cell.

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
* HCTR++ and BBB-DDD-AES numbers are stable across runs and builds (within
  0.03 cpb from 1 KiB up). PHCTR+ is sensitive to code layout: builds of
  byte-identical object code (different link order, or unrelated changes
  elsewhere in the binary) measure between 0.85 and 1.12 cpb at 64 KiB.
  The build as committed measures 0.85-0.88 cpb at 64 KiB.
* CHCTR2 costs 2 AES calls and 3 GF(2^128) multiplications per block; the
  two middle hash layers are merged into one pass over precomputed
  `H1^j ^ H2^j`. Its setup (~150k cycles, once per key) is dominated by
  that 4104-entry table. Inputs above ~64 KiB fall back to two passes
  (4 multiplications per block); all measured sizes use the merged pass.
* HCTR2-TwKD runs at HCTR2's per-block cost (1 AES call, 2
  multiplications) but derives and schedules a fresh key on every message:
  3 KDF AES calls (2 for TwKD-128), HCTR2 subkeys and POLYVAL key powers,
  and upstream's portable C AES key expansion (~220 / 315 cycles, the
  setup row). That fixed cost dominates at small messages.
* At 64 KiB, CHCTR2-256 / TwKD-256 = 1.62. Upstream's own WSL2
  measurement on this machine gives 1.61; the paper reports 1.67 on Zen 5.
  AES-256 costs these modes 10-12% at 64 KiB against AES-128.
* PHCTR+ reaches TBC speed with Deoxys-BC, a non-standard primitive;
  HCTR++ and BBB-DDD-AES use plain AES-128. Security: HCTR++ O(2^n) (tweak-
  reuse dependent), BBB-DDD-AES O(2^{2n/3}), HCTR+ O(2^n) (paper, Table 1).
  CHCTR2 has 2n/3-bit multi-user security with no limit on tweak reuse.
  HCTR2-TwKD has 2n/3-bit security while one tweak processes at most about
  2^{n/3} blocks (ePrint 2026/085).
* All schemes are structurally symmetric; decryption performance matches
  encryption.

## Licenses

This implementation, including `bench/`: MIT. `vendor/bbb-ddd-aes-perf/` is
Intel's MIT-licensed code with marked benchmark patches. The HCTR_PLUS and
CHCTR-HCTR2TwKD sources are linked from the sibling checkouts, not copied.
The latter's x86-64 assembly comes from the Linux kernel and is GPLv2 (one
file dual GPLv2/BSD-3). The `benchmark` binary links it, so redistributing
that binary must follow GPLv2.
