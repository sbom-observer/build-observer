CLANG ?= clang
CFLAGS := -g -O2 -Wall
BPFTOOL ?= bpftool

all: traceopens

%.bpf.o: %.bpf.c
	$(CLANG) -target bpf -D__TARGET_ARCH_x86 $(CFLAGS) -c $< -o $@

%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

traceopens: traceopens.c traceopens.skel.h traceopens.h
	$(CC) $(CFLAGS) -o $@ $< -lbpf -lelf

clean:
	rm -f *.o *.skel.h traceopens 