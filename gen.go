package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir ebpf -target amd64 -tags linux vfs_monitor_create src/create.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir ebpf -target amd64 -tags linux vfs_monitor_delete src/delete.bpf.c
