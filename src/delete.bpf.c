#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "vfs_monitor.bpf.h"


SEC("fexit/vfs_rmdir")
int BPF_PROG(vfs_rmdir_hook){

    return 0;
}



SEC("fexit/vfs_unlink")
int BPF_PROG(vfs_unlink_hook){
    return 0;
}