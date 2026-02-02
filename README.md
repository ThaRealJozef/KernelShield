# KernelShield

KernelShield is an experimental eBPF security engine built to explore Linux kernel internals. It combines high-performance network filtering (XDP) with system integrity monitoring (Kprobes/Tracepoints) into a unified Go-controlled framework.

## Architecture

The project implements a "split-brain" design:
*   **Kernel Enforcer (C)**: BPF programs running in-kernel for line-rate performance.
    *   `xdp_firewall.c`: Network-layer filtering.
    *   `sys_monitor.c`: Syscall auditing via Ring Buffers.
*   **User Controller (Go)**: A daemon managing the BPF lifecycle, map updates, and event streaming using `cilium/ebpf`.

## Features

*   **XDP Firewall**: Drops unauthorized IPv4 traffic at the NIC driver level, before the stack processes it.
*   **Syscall Sentry**: Monitors `sys_openat` and `sys_openat2` to detect access to sensitive files (e.g., `/etc/shadow`) in real-time.
*   **CO-RE Enabled**: Uses `vmlinux.h` for Compile-Once Run-Everywhere support across different kernel versions.

## Prerequisites

*   **Platform**: Linux with BTF enabled (tested on WSL2 Ubuntu).
*   **Kernel**: 5.4+ (5.8+ recommended for Ring Buffer support).
*   **Tools**: `clang`, `llvm`, `make`, `bpftool`, `go 1.22+`.

## Build & Usage

```bash
# 1. Install dependencies
sudo apt update && sudo apt install clang llvm libbpf-dev bpftool make golang-go

# 2. Build kernel and user space components
make all

# 3. Running (Requires root to load BPF)
sudo ./kernelshield
```

Once running, you can verify the system monitor by accessing a sensitive file in another terminal:
`cat /etc/shadow`

The controller will alert:
`[ALERT] 🚨 SENSITIVE FILE ACCESS: Process 'cat' (PID 1234) opened /etc/shadow`

## License
Dual BSD/GPL

