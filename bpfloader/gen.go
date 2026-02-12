package bpfloader

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -output-dir . -tags linux fim ../src/fim.bpf.c
