CFLAGS ?= -DIGNORESIG0
CONTAINER ?= charlie0129/killsnoop

all: killsnoop

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

bpf_bpfel.go: vmlinux.h main.bpf.c
	GOPACKAGE=main go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf main.bpf.c -- $(CFLAGS) >/dev/null

.PHONY: killsnoop
killsnoop: bpf_bpfel.go
	CGO_ENABLED=0 GOOS=linux go build \
		-asmflags="all=-trimpath=$$(pwd)" \
		-gcflags="all=-trimpath=$$(pwd)" \
		-ldflags="-s -w" \
		-o=killsnoop .

.PHONY: container
container: killsnoop
	docker build . -t $(CONTAINER):$(shell ./getversion.sh)

clean:
	rm -f bpf_*.o bpf_*.go vmlinux.h killsnoop
