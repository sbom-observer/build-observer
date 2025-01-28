# .PRECIOUS: %.bpf.o

CLANG ?= clang
CFLAGS := -g -O2 -Wall -I../bpf/headers
BPFTOOL ?= bpftool

all: build-observer

../bpf/headers/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > ../bpf/headers/vmlinux.h

%.bpf.o: ../bpf/%.bpf.c ../bpf/headers/vmlinux.h
	$(CLANG) -target bpf -D__TARGET_ARCH_x86 $(CFLAGS) -c $< -o $@

%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

build-observer: build-observer.c traceopens.skel.h ../bpf/headers/traceopens.h ../bpf/headers/vmlinux.h
	$(CC) $(CFLAGS) -o $@ $< -lbpf -lelf

build-observer-ptrace: build-observer-ptrace.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f *.o *.skel.h build-observer build-observer-ptrace