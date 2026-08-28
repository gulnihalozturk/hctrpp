CC = gcc
FLAGS = -O3 -march=native -Wall -Wextra
HCTR_PLUS = ../HCTR_PLUS

all: hctrpp_validation benchmark3

hctrpp_validation: hctrpp_validation.c src/hctrpp.c include/hctrpp.h testvectors/hctrpp_kat.h
	$(CC) $(FLAGS) hctrpp_validation.c -o $@

# Three-way comparison; needs the sibling checkouts ../HCTR_PLUS (linked
# directly) and the vendored Intel BBB-DDD-AES performance implementation.
benchmark3: benchmark3.c src/hctrpp.c include/hctrpp.h \
            vendor/bbb-ddd-aes-perf/bbb-ddd-aes-ref-perf.c
	$(CC) $(FLAGS) -Wformat=0 -I$(HCTR_PLUS)/include \
	    benchmark3.c src/hctrpp.c \
	    vendor/bbb-ddd-aes-perf/bbb-ddd-aes-ref-perf.c \
	    $(HCTR_PLUS)/src/hctr+phash.c $(HCTR_PLUS)/src/deoxysbc.c \
	    $(HCTR_PLUS)/src/init.c $(HCTR_PLUS)/src/utility.c \
	    -o $@

# Regenerate testvectors/hctrpp_kat.h from the executable specification
kat:
	python python/hctrpp.py testvectors/hctrpp_kat.h

clean:
	rm -f hctrpp_validation hctrpp_validation.exe benchmark3 benchmark3.exe

.PHONY: all kat clean
