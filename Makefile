
# Make file for ease
# generate: get vmlinux.h from the targeted kernel
# I know one way i.e just boot it on qemu and run the generate section below
# their might be a way to do this in kernel build process

all: generate
	go build
run:
	./vfs_ops_monitor

generate: src/* bpfInterface/gen.go
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h
	go generate ./bpfInterface


clean:
	go clean -cache -testcache
	rm bpfInterface/vfslsm* vfs_ops_monitor
	