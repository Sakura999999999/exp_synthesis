#include "heap_api.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define IOCTL_MAGIC             'Y'
#define IOCTL_ALLOC_VULOBJ      _IOWR(IOCTL_MAGIC, 0x01, int)
#define IOCTL_FREE_VULOBJ       _IOW(IOCTL_MAGIC, 0x02, int)
#define IOCTL_WRITE_VULOBJ      _IOW(IOCTL_MAGIC, 0x03, int)
#define IOCTL_READ_VICTIM       _IOR(IOCTL_MAGIC, 0x04, int)
#define IOCTL_EXECUTE_VICTIM    _IOW(IOCTL_MAGIC, 0x05, int)
#define IOCTL_ALLOC_VICTIM      _IOWR(IOCTL_MAGIC, 0x06, int)
#define IOCTL_FREE_VICTIM       _IOW(IOCTL_MAGIC, 0x07, int)
#define IOCTL_ALLOC_DUMMY       _IOWR(IOCTL_MAGIC, 0x08, int)
#define IOCTL_FREE_DUMMY        _IOW(IOCTL_MAGIC, 0x09, int)
#define IOCTL_GET_ADDR          _IOWR(IOCTL_MAGIC, 0x0A, struct addr_arg)
#define IOCTL_ALLOC_DEFRAG      _IOWR(IOCTL_MAGIC, 0x0B, int)

int heap_verbose = 1;

struct request_arg {
    int handler;
    int offset;
    char value;
};

struct addr_arg {
    int type;
    int handler;
    unsigned long addr;
};

static const char *type_name(int type) {
    switch (type) {
        case HEAP_OBJ_VUL:    return "VUL";
        case HEAP_OBJ_VICTIM: return "VICTIM";
        case HEAP_OBJ_DUMMY:  return "DUMMY";
        case HEAP_OBJ_DEFRAG: return "DEFRAG";
        default:              return "?";
    }
}

static unsigned long type_alloc_cmd(int type) {
    switch (type) {
        case HEAP_OBJ_VUL:    return IOCTL_ALLOC_VULOBJ;
        case HEAP_OBJ_VICTIM: return IOCTL_ALLOC_VICTIM;
        case HEAP_OBJ_DUMMY:  return IOCTL_ALLOC_DUMMY;
        case HEAP_OBJ_DEFRAG: return IOCTL_ALLOC_DEFRAG;
        default:              return 0;
    }
}

static unsigned long type_free_cmd(int type) {
    switch (type) {
        case HEAP_OBJ_VUL:    return IOCTL_FREE_VULOBJ;
        case HEAP_OBJ_VICTIM: return IOCTL_FREE_VICTIM;
        case HEAP_OBJ_DUMMY:  return IOCTL_FREE_DUMMY;
        default:              return 0;
    }
}

static int heap_alloc(int fd, int type, size_t count, int *out) {
    unsigned long cmd = type_alloc_cmd(type);
    size_t i;

    for (i = 0; i < count; i++) {
        int handle = 0;
        if (ioctl(fd, cmd, &handle) < 0) {
            perror("[-] alloc ioctl failed");
            return -1;
        }
        if (out != NULL) {
            out[i] = handle;
        }
        if (heap_verbose) {
            unsigned long addr = 0;
            if (heap_get_addr(fd, type, handle, &addr) == 0) {
                printf("[+] alloc %-6s [%d] @ 0x%lx\n", type_name(type), handle, addr);
            } else {
                printf("[+] alloc %-6s [%d]\n", type_name(type), handle);
            }
        }
    }

    return 0;
}

static int heap_free(int fd, int type, int idx) {
    unsigned long cmd = type_free_cmd(type);
    int handle = idx;
    unsigned long addr = 0;
    int have_addr = 0;

    if (heap_verbose) {
        have_addr = (heap_get_addr(fd, type, idx, &addr) == 0);
    }

    if (ioctl(fd, cmd, &handle) < 0) {
        perror("[-] free ioctl failed");
        return -1;
    }

    if (heap_verbose) {
        if (have_addr) {
            printf("[-] free  %-6s [%d] @ 0x%lx\n", type_name(type), idx, addr);
        } else {
            printf("[-] free  %-6s [%d]\n", type_name(type), idx);
        }
    }

    return 0;
}

int heap_alloc_vul(int fd, size_t count, int *out) {
    return heap_alloc(fd, HEAP_OBJ_VUL, count, out);
}

int heap_free_vul(int fd, int idx) {
    return heap_free(fd, HEAP_OBJ_VUL, idx);
}

int heap_write_vul(int fd, int idx, int offset, char value) {
    struct request_arg req;

    req.handler = idx;
    req.offset = offset;
    req.value = value;

    if (ioctl(fd, IOCTL_WRITE_VULOBJ, &req) < 0) {
        perror("[-] write vuln ioctl failed");
        return -1;
    }

    return 0;
}

int heap_alloc_victim(int fd, size_t count, int *out) {
    return heap_alloc(fd, HEAP_OBJ_VICTIM, count, out);
}

int heap_free_victim(int fd, int idx) {
    return heap_free(fd, HEAP_OBJ_VICTIM, idx);
}

int heap_execute_victim(int fd, int idx) {
    int handle = idx;

    if (ioctl(fd, IOCTL_EXECUTE_VICTIM, &handle) < 0) {
        perror("[-] execute victim ioctl failed");
        return -1;
    }

    return 0;
}

#define VICTIM_SIZE 16

int heap_read_victim(int fd, int idx) {
    unsigned char buf[VICTIM_SIZE];
    unsigned long funptr = 0;
    int i, j;

    for (i = 0; i < VICTIM_SIZE; i++) {
        struct request_arg req;
        req.handler = idx;
        req.offset = i;
        req.value = 0;
        if (ioctl(fd, IOCTL_READ_VICTIM, &req) < 0) {
            perror("[-] read victim ioctl failed");
            return -1;
        }
        buf[i] = (unsigned char)req.value;
    }

    for (i = 0; i < (int)sizeof(unsigned long); i++) {
        funptr |= ((unsigned long)buf[i]) << (i * 8);
    }

    printf("[*] victim[%d]'s first %d bytes content:\n", idx, VICTIM_SIZE);
    for (i = 0; i < VICTIM_SIZE; i += 16) {
        printf("    %04x:", i);
        for (j = 0; j < 16 && i + j < VICTIM_SIZE; j++) {
            printf(" %02x", buf[i + j]);
        }
        printf("\n");
    }

    return 0;
}

int heap_alloc_dummy(int fd, size_t count, int *out) {
    return heap_alloc(fd, HEAP_OBJ_DUMMY, count, out);
}

int heap_free_dummy(int fd, int idx) {
    return heap_free(fd, HEAP_OBJ_DUMMY, idx);
}

int heap_alloc_defrag(int fd, size_t count, int *out) {
    return heap_alloc(fd, HEAP_OBJ_DEFRAG, count, out);
}

#define OBJS_PER_SLAB 8
#define DEFRAG_CONSECUTIVE_FRESH 2
#define DEFRAG_MAX_SPRAY 4096

int heap_defrag(int fd) {
    int prev_verbose;
    int total = 0;
    int fresh_runs = 0;
    int run_length = 0;
    unsigned long current_base = 0;
    int rc = -1;

    printf("[*] defrag until %d consecutive full-slab runs\n", DEFRAG_CONSECUTIVE_FRESH);

    prev_verbose = heap_verbose;
    heap_verbose = 0;

    while (total < DEFRAG_MAX_SPRAY) {
        int handle = 0;
        unsigned long addr = 0;
        unsigned long base;

        if (heap_alloc_defrag(fd, 1, &handle) < 0) {
            goto out;
        }
        if (heap_get_addr(fd, HEAP_OBJ_DEFRAG, handle, &addr) < 0) {
            goto out;
        }
        total++;
        base = addr & ~0xFFFUL;

        if (base == current_base) {
            run_length++;
        } else {
            if (run_length > 0 && run_length < OBJS_PER_SLAB) {
                fresh_runs = 0;
            }
            current_base = base;
            run_length = 1;
        }

        if (run_length == OBJS_PER_SLAB) {
            fresh_runs++;
            if (fresh_runs >= DEFRAG_CONSECUTIVE_FRESH) {
                rc = total;
                goto out;
            }
            run_length = 0;
            current_base = 0;
        }
    }

    printf("[-] defrag failed to converge within %d defrags\n", DEFRAG_MAX_SPRAY);

out:
    heap_verbose = prev_verbose;
    if (rc >= 0) {
        printf("[+] defrag converged after %d defrags (%d consecutive full slabs)\n",
               total, fresh_runs);
    }
    return rc;
}

int heap_get_addr(int fd, int type, int idx, unsigned long *addr) {
    struct addr_arg req;

    req.type = type;
    req.handler = idx;
    req.addr = 0;

    if (ioctl(fd, IOCTL_GET_ADDR, &req) < 0) {
        perror("[-] get_addr ioctl failed");
        return -1;
    }

    *addr = req.addr;
    return 0;
}
