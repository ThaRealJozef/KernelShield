CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -Werror

# The path to the Go binary
GO ?= go

# The path to the compiled BPF object file
BPF_OBJ = bpf_bpfel.o bpf_bpfeb.o

.PHONY: all generate build clean

all: generate build

generate:
	export BPF_CLANG=$(CLANG); \
	export BPF_CFLAGS="$(CFLAGS)"; \
	cd cmd/kernelshield && $(GO) generate ./...

build:
	cd cmd/kernelshield && $(GO) build -o ../../kernelshield

clean:
	rm -f cmd/kernelshield/$(BPF_OBJ)
	rm -f kernelshield
