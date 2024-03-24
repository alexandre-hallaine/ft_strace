#pragma once

#include <sys/types.h>

extern pid_t child_pid;

typedef enum e_arch {
    ARCH_32,
    ARCH_64,
} t_arch;

typedef enum e_type {
    UNKNOWN = 0,

    PTR,

    CHAR,
    STR,

    SHORT,
    INT,
    LONG,

    ARRAY = 1 << 3,

    DEV = LONG,
    INO = LONG,
    MODE = INT,
    ID = INT,
    OFF = LONG,
    TIME = LONG,

    UNKNOWN_STRUCT = PTR,
} t_type;

typedef struct s_syscall {
    char *name;
    t_type args[7];
    t_type ret;
} t_syscall;

// address are stored as long
typedef struct s_stop {
    t_arch arch;
    t_syscall *syscall;
    long args[6];
    long ret;
} t_stop;

struct user_regs_struct_64
{
    long long r15;
    long long r14;
    long long r13;
    long long r12;
    long long rbp;
    long long rbx;
    long long r11;
    long long r10;
    long long r9;
    long long r8;
    long long rax;
    long long rcx;
    long long rdx;
    long long rsi;
    long long rdi;
    long long orig_rax;
    long long rip;
    long long cs;
    long long eflags;
    long long rsp;
    long long ss;
    long long fs_base;
    long long gs_base;
    long long ds;
    long long es;
    long long fs;
    long long gs;
};

struct user_regs_struct_32
{
    int ebx;
    int ecx;
    int edx;
    int esi;
    int edi;
    int ebp;
    int eax;
    int xds;
    int xes;
    int xfs;
    int xgs;
    int orig_eax;
    int eip;
    int xcs;
    int eflags;
    int esp;
    int xss;
};
