//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// EPERM is usually 1. Return -EPERM to deny.
#define EPERM 1

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file, int mask) {
    // Read the filename from file->f_path.dentry->d_name.name
    struct qstr d_name = BPF_CORE_READ(file, f_path.dentry, d_name);
    const char *name = (const char *)d_name.name;
    
    char filename[16];
    bpf_probe_read_kernel_str(&filename, sizeof(filename), name);
    
    // Verify filename against sensitive target "shadow"
    // Note: Production implementations should use a BPF Map for dynamic path matching
    if (filename[0] == 's' && filename[1] == 'h' && filename[2] == 'a' && 
        filename[3] == 'd' && filename[4] == 'o' && filename[5] == 'w' && filename[6] == '\0') {
               
        bpf_printk("LSM: Blocking access to %s\n", filename);
        return -EPERM;
    }

    return 0;
}
