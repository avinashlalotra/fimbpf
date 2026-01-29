
# Make file for ease
# generate: get vmlinux.h from the targeted kernel
# I know one way i.e just boot it on qemu and run the generate section below
# their might be a way to do this in kernel build process

all:
	go build
run:
	./vfs_ops_monitor

generate:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h
	mkdir -p ebpf
	go generate

clean:
	rm ebpf/*  vfs_ops_monitor