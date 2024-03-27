#include "types.h"

#include <stdio.h>
#include <stdlib.h>

#define __USE_GNU
#include <sys/uio.h>

long limit_value(long value, int size) {
    if (size > (int)sizeof(long)) return 0;
    if (size == (int)sizeof(long)) return value;

    long convertore = 1;
    convertore <<= size * 8;
    convertore -= 1;
    
    return value & convertore;
}

void *read_data(void *addr, size_t size) {
    struct iovec data[2] = {
        { malloc(size), size },
        { addr, size },
    };

    ssize_t ret = process_vm_readv(child_pid, data, 1, data + 1, 1, 0);
    if (ret != -1) return data->iov_base;

    free(data->iov_base);
    return NULL;
}

void print_type(t_type type, long value) {
    if (type == PTR) return (void)printf("%p", (void *)value);

    void *allocated = NULL;
    if (type == STR) allocated = read_data((void *)value, 4096);
    if (allocated != NULL) value = (long)allocated;

    switch (type) {
        case CHAR:
            printf("%c", (char)value);
            break;
        case STR:
            if (value == 0)
                printf("%p", (void *)value);
            else
                printf("\"%s\"", (char *)value);
            break;
        case SHORT:
            printf("%hd", (short)value);
            break;
        case INT:
            printf("%d", (int)value);
            break;
        case LONG:
            printf("%ld", (long)value);
            break;
        default:
            printf("?");
    }

    if (allocated != NULL) free(allocated);
}

void print_value(t_type type, long value, t_arch arch) {
    int ptr_size = arch == ARCH_64 ? 8 : 4;
    value = limit_value(value, ptr_size);

    if (!(type & ARRAY)) return print_type(type, value);
    type &= ~ARRAY;
    if ((type != PTR && type != STR)) return print_type(PTR, value);

    void *allocated = read_data((void *)value, 4096);
    if (allocated != NULL) value = (long)allocated;
    printf("[");

    for (long i = 0; *(void **)(value + i) != NULL; i += ptr_size) {
        if (i) printf(", ");
        print_type(type, *(long *)(value + i));
    }

    printf("]");
    if (allocated != NULL) free(allocated);
}
