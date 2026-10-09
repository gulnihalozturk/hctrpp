CC = gcc
FLAGS = -O3 -march=native -Wall -Wextra
HCTR_PLUS = ../HCTR_PLUS
CHCTR = ../CHCTR-HCTR2TwKD
BUILD = build
# python3 where it runs (Linux has no `python`; on Windows it may be a stub)
PYTHON ?= $(shell python3 -c "" >/dev/null 2>&1 && echo python3 || echo python)

all: hctrpp_validation benchmark

hctrpp_validation: hctrpp_validation.c src/hctrpp.c include/hctrpp.h testvectors/hctrpp_kat.h
	$(CC) $(FLAGS) hctrpp_validation.c -o $@

# CHCTR2 / HCTR2-TwKD objects, compiled from the sibling checkout
# ../CHCTR-HCTR2TwKD (not copied) with that project's language flags, plus
# the adapter in bench/.  Its frozen test vectors are converted to C with
# its own generator for the benchmark's self-test.
CHCTR_SRC = $(CHCTR)/benchmark/src
CHCTR_LK = $(CHCTR)/third_party/linux-kernel
CHCTR_VECTORS = $(CHCTR)/test_vectors/reference/v1/chctr2-aes256-polyval-v1.json \
                $(CHCTR)/test_vectors/reference/v1/hctr2-twkd-cenc126-aes256-polyval-v1.json
CHCTR_INC = -Ibench -I$(CHCTR_SRC) -I$(CHCTR)/benchmark/tests -I$(CHCTR_LK)
CHCTR_CFLAGS = -O3 -march=native -std=gnu11 -Wall -Wno-pointer-sign \
               -fno-strict-aliasing -fwrapv -MMD -MP $(CHCTR_INC)
CHCTR_C = aes.c chctr2.c hctr2.c hctr2_twkd.c polyval.c polyval_xor.c xctr.c \
          polyval_xor_clmul.c aes_ti.c gf128.c chctr_glue.c
CHCTR_ASM = polyval-clmulni_asm.S aes_ctrby8_avx-x86_64.S aesni-intel_asm.S
CHCTR_OBJ = $(addprefix $(BUILD)/chctr/,$(CHCTR_C:.c=.o) $(CHCTR_ASM:.S=.o) \
                                        conformance_vectors.o)

vpath %.c bench $(CHCTR_SRC) $(CHCTR_SRC)/x86_64 $(CHCTR_LK)
vpath %.S $(CHCTR_SRC)/x86_64 $(CHCTR_LK)/x86_64

$(BUILD)/chctr/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CHCTR_CFLAGS) -c $< -o $@

$(BUILD)/chctr/conformance_vectors.c: $(CHCTR)/tools/vectors_to_c.py $(CHCTR_VECTORS)
	@mkdir -p $(@D)
	$(PYTHON) $^ $@

$(BUILD)/chctr/conformance_vectors.o: $(BUILD)/chctr/conformance_vectors.c
	$(CC) $(CHCTR_CFLAGS) -c $< -o $@

ifneq ($(findstring mingw,$(shell $(CC) -dumpmachine)),)
# The Linux-kernel assembly is SysV-ABI ELF source.  For MinGW, rename its
# entry points to sysv_* (bench/win64_sysv_thunks.c provides the original
# names under the Microsoft x64 ABI) and rewrite the ELF-only section
# directives for PE/COFF.  COFF has no section stack; in these sources
# .pushsection always enters read-only data and .popsection / .previous
# always return to .text.
CHCTR_ASM_SYMS = clmul_polyval_update clmul_polyval_mul \
                 aesni_ecb_enc aesni_ecb_dec aes_xctr_enc_128_avx_by8 \
                 aes_xctr_enc_192_avx_by8 aes_xctr_enc_256_avx_by8
CHCTR_OBJ += $(BUILD)/chctr/win64_sysv_thunks.o

$(BUILD)/chctr/%.o: %.S
	@mkdir -p $(@D)
	$(CC) -E $(CHCTR_INC) $(foreach s,$(CHCTR_ASM_SYMS),-D$(s)=sysv_$(s)) \
	    $< -o $(@:.o=.pre)
	sed -E -e 's/\.(push)?section[[:space:]]+\.rodata[^;]*/.section .rdata,"dr"/' \
	       -e 's/^[[:space:]]*\.(popsection|previous)[[:space:]]*$$/.text/' \
	       -e 's/\.type[[:space:]]+[A-Za-z0-9_]+[[:space:]]+STT_FUNC;?//' \
	       $(@:.o=.pre) > $(@:.o=.s)
	$(CC) -c $(@:.o=.s) -o $@
else
$(BUILD)/chctr/%.o: %.S
	@mkdir -p $(@D)
	$(CC) -c $(CHCTR_INC) $< -o $@
endif

-include $(CHCTR_OBJ:.o=.d)

# Five-scheme comparison; needs the sibling checkouts ../HCTR_PLUS and
# ../CHCTR-HCTR2TwKD (both linked directly) and the vendored Intel
# BBB-DDD-AES performance implementation.
benchmark: benchmark.c src/hctrpp.c include/hctrpp.h bench/chctr_glue.h \
           vendor/bbb-ddd-aes-perf/bbb-ddd-aes-ref-perf.c $(CHCTR_OBJ)
	$(CC) $(FLAGS) -Wformat=0 -I$(HCTR_PLUS)/include \
	    benchmark.c src/hctrpp.c \
	    vendor/bbb-ddd-aes-perf/bbb-ddd-aes-ref-perf.c \
	    $(HCTR_PLUS)/src/hctr+phash.c $(HCTR_PLUS)/src/deoxysbc.c \
	    $(HCTR_PLUS)/src/init.c $(HCTR_PLUS)/src/utility.c \
	    $(CHCTR_OBJ) -o $@

# Regenerate testvectors/hctrpp_kat.h from the executable specification
kat:
	$(PYTHON) python/hctrpp.py testvectors/hctrpp_kat.h

clean:
	rm -f hctrpp_validation hctrpp_validation.exe benchmark benchmark.exe
	rm -rf $(BUILD)

.PHONY: all kat clean
