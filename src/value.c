#include "types.h"

#include <stdio.h>
#include <stdlib.h>

#define __USE_GNU
#include <sys/uio.h>

void *read_data(void *addr, size_t size) {
    struct iovec data[2] = {
        { malloc(size), size },
        { addr, size },
    };

    ssize_t ret = process_vm_readv(child_pid, data, 1, data + 1, 1, 0);

    if (ret != -1)
        return data->iov_base;
    free(data->iov_base);
    return NULL;
}

int size_type(t_type type) {
    switch (type) {
        case PTR:
            return sizeof(void *);

        case CHAR:
            return sizeof(char);
        case STR:
            return sizeof(char *);

        case SHORT:
            return sizeof(short);
        case INT:
            return sizeof(int);
        case LONG:
            return sizeof(long);

        default:
            return 0;
    }
}

void print_type(t_type type, void *value) {
    if (type == PTR) {
        if (*(void **)value == NULL) printf("NULL");
        else printf("%p", *(void **)value);
        return;
    }

    void *allocated = read_data(*(void **)value, size_type(type) * 4096);
    if (allocated != NULL) value = &allocated;

    if (type == CHAR)
        printf("%c", *(char *)value);
    else if (type == STR)
        printf("\"%s\"", *(char **)value);
    else if (type == SHORT)
        printf("%hd", *(short *)value);
    else if (type == INT)
        printf("%d", *(int *)value);
    else if (type == LONG)
        printf("%ld", *(long *)value);
    else
        printf("?");

    if (allocated != NULL) free(allocated);
}

void print_value(t_type type, void *value) {
    if (!(type & ARRAY)) {
        print_type(type, value);
        return;
    }

    type &= ~ARRAY;
    value = *(void **)value;
    unsigned long i = 0;
    printf("[");

    for (; *(void **)(value + i); i += size_type(type)) {
        if (i)
            printf(", ");
        print_type(type, value + i);
    }

    printf("]");
}
