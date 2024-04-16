# ft_strace

## Introduction

ft_strace is a system call tracing tool for Linux and other Unix-like systems.  It leverages the `ptrace` mechanism to monitor and display the system calls executed by a specified program. If you're familiar with the standard `strace` utility, ft_strace offers a similar experience.

## Key Features

* Traces system calls on both x86 and x86_64 architectures.
* Handles potential errors and signal-induced terminations.

## Usage

1. Compile the project using `make`.
2. Run ft_strace: 
   ```bash
   ./ft_strace <program> [<program arguments>]
   ```

## Test

The `test` folder contains example programs to demonstrate ft_strace:

- `segfault`: A program designed to trigger a segmentation fault.
- `32`: A 32-bit "Hello World!" program.
- `64`: A 64-bit "Hello World!" program.

## Example

```bash
$ ./ft_strace test/segfault 
execve("test/segfault", ["test/segfault"], [...]) = 0
brk((nil)) = -213794816
arch_prctl(12289, 0x7ffd5977da20) = -22
access("/etc/ld.so.preload", 4) = -2
openat(-100, "/etc/ld.so.cache", 524288, 0) = 3
newfstatat(3, "", 0x7ffd5977cc30, 4096) = 0
mmap((nil), 77055, 1, 2, 3, 0) = 0x7f7808128000
close(3) = 0
openat(-100, "/lib64/libc.so.6", 524288, 0) = 3
read(3, 0x7ffd5977cd98, 832) = 832
pread64(3, 0x7ffd5977c9b0, 784, 64) = 784
newfstatat(3, "", 0x7ffd5977cc30, 4096) = 0
mmap((nil), 8192, 3, 34, -1, 0) = 0x7f7808126000
pread64(3, 0x7ffd5977c880, 784, 64) = 784
mmap((nil), 1973104, 1, 2050, 3, 0) = 0x7f7807f44000
mmap(0x7f7807f6a000, 1441792, 5, 2066, 3, 155648) = 0x7f7807f6a000
mmap(0x7f78080ca000, 319488, 1, 2066, 3, 1597440) = 0x7f78080ca000
mmap(0x7f7808118000, 24576, 3, 2066, 3, 1912832) = 0x7f7808118000
mmap(0x7f780811e000, 31600, 3, 50, -1, 0) = 0x7f780811e000
close(3) = 0
mmap((nil), 8192, 3, 34, -1, 0) = 0x7f7807f42000
arch_prctl(4098, 0x7f7808127680) = 0
set_tid_address(0x7f7808127950) = 11885
set_robust_list(0x7f7808127960, 24) = 0
rseq() = ?
mprotect(0x7f7808118000, 16384, 1) = 0
mprotect(0x5639f1cb7000, 4096, 1) = 0
mprotect(0x7f780816d000, 8192, 1) = 0
prlimit64(0, 3, (nil), 0x7ffd5977d780) = 0
munmap(0x7f7808128000, 77055) = 0
+++ killed by Segmentation fault +++
```
