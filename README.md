# KernelShield 🛡️

**KernelShield** is an experimental eBPF-based firewall I'm building to learn more about the Linux kernel's networking subsystems. 

The goal was to move security logic out of user space (which is slow) and strictly into the kernel using **XDP (eXpress Data Path)**. This allows the program to drop malicious packets at the driver level—before the OS even expends resources allocating memory for them.

## Technical Architecture

The project follows a split-brain architecture:

1.  **Kernel Space (C)**: An XDP program (`xdp_firewall.c`) that hooks into the network interface. It parses Ethernet and IP headers to make split-second Drop/Pass decisions.
2.  **User Space (Go)**: A controller daemon that uses `cilium/ebpf` to manage the kernel program. It handles the lifecycle, loads BPF maps, and populates the blocklist.

## Current Features

- ⚡ **Line-Rate Filtering**: Packets are processed directly in the network driver path.
- 🚫 **Dynamic Blocklisting**: The Go controller can push IP addresses to a BPF Hash Map to instantly drop traffic without reloading the program.
- 📊 **Telemetry**: Real-time packet counters (Allowed vs Dropped) tracking flow stats from the kernel.

## Getting Started

I built this on WSL2, but it should run on any modern Linux kernel (5.4+) with BTF support.

### Prerequisites
- Clang/LLVM 10+
- Go 1.20+
- `bpftool`

### Build & Run
```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install clang llvm libbpf-dev bpftool make golang-go

# Compile C BPF and Go binaries
make all

# Run the controller (requires root to load BPF)
sudo ./kernelshield
```

## Future Roadmap

I'm checking out **Kprobes** next—the plan is to monitor system calls (like `sys_openat`) to detect when specific files (like `/etc/shadow`) are accessed by unauthorized processes.

## License
Dual BSD/GPL

