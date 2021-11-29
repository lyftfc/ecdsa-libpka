HDRS := ec_curves.h testvec.h ecdsa_utils.h
CFLAGS := -I../lib -g
LIB := /usr/lib/aarch64-linux-gnu/libPKA.so

ecdsa_benchmark: ecdsa_benchmark.o ecdsa_utils.o
	gcc -o $@ $^ $(LIB)

%.o : %.c $(HDRS)
	gcc -c $(CFLAGS) -o $@ $<

myecc: $(HDRS) $(SRCS)
	gcc $(CFLAGS) -o $@ myecc.c $(LIB)

clean:
	@rm ecdsa_benchmark myecc ./*.o

.PHONY: clean
