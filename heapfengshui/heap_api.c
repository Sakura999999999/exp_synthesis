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

static int heap_verbose = 1;

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

static int heap_check_ctx(heap_ctx_t *ctx) {
    if (ctx == NULL || ctx->fd < 0) {
        errno = EBADF;
        fprintf(stderr, "[-] heap context is not initialized\n");
        return -1;
    }
    return 0;
}

int heap_open(heap_ctx_t *ctx, const char *device_path) {
    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    ctx->fd = open(device_path, O_RDWR);
    if (ctx->fd < 0) {
        perror("[-] open device failed");
        return -1;
    }

    return 0;
}

void heap_close(heap_ctx_t *ctx) {
    if (ctx != NULL && ctx->fd >= 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }
}

static int heap_alloc(heap_ctx_t *ctx, int type, size_t count, int *out) {
    unsigned long cmd = type_alloc_cmd(type);
    size_t i;

    if (heap_check_ctx(ctx) < 0) {
        return -1;
    }

    for (i = 0; i < count; i++) {
        int handle = 0;
        if (ioctl(ctx->fd, cmd, &handle) < 0) {
            perror("[-] alloc ioctl failed");
            return -1;
        }
        if (out != NULL) {
            out[i] = handle;
        }
        if (heap_verbose) {
            unsigned long addr = 0;
            if (heap_get_addr(ctx, type, handle, &addr) == 0) {
                printf("[+] alloc %-6s [%d] @ 0x%lx\n", type_name(type), handle, addr);
            } else {
                printf("[+] alloc %-6s [%d]\n", type_name(type), handle);
            }
        }
    }

    return 0;
}

static int heap_free(heap_ctx_t *ctx, int type, int idx) {
    unsigned long cmd = type_free_cmd(type);
    int handle = idx;
    unsigned long addr = 0;
    int have_addr = 0;

    if (heap_check_ctx(ctx) < 0) {
        return -1;
    }

    if (heap_verbose) {
        have_addr = (heap_get_addr(ctx, type, idx, &addr) == 0);
    }

    if (ioctl(ctx->fd, cmd, &handle) < 0) {
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

int heap_alloc_vul(heap_ctx_t *ctx, size_t count, int *out) {
    return heap_alloc(ctx, HEAP_OBJ_VUL, count, out);
}

int heap_free_vul(heap_ctx_t *ctx, int idx) {
    return heap_free(ctx, HEAP_OBJ_VUL, idx);
}

int heap_write_vul(heap_ctx_t *ctx, int idx, int offset, char value) {
    struct request_arg req;

    if (heap_check_ctx(ctx) < 0) {
        return -1;
    }

    req.handler = idx;
    req.offset = offset;
    req.value = value;

    if (ioctl(ctx->fd, IOCTL_WRITE_VULOBJ, &req) < 0) {
        perror("[-] write vuln ioctl failed");
        return -1;
    }

    return 0;
}

int heap_alloc_victim(heap_ctx_t *ctx, size_t count, int *out) {
    return heap_alloc(ctx, HEAP_OBJ_VICTIM, count, out);
}

int heap_free_victim(heap_ctx_t *ctx, int idx) {
    return heap_free(ctx, HEAP_OBJ_VICTIM, idx);
}

int heap_execute_victim(heap_ctx_t *ctx, int idx) {
    int handle = idx;

    if (heap_check_ctx(ctx) < 0) {
        return -1;
    }

    if (ioctl(ctx->fd, IOCTL_EXECUTE_VICTIM, &handle) < 0) {
        perror("[-] execute victim ioctl failed");
        return -1;
    }

    return 0;
}

#define VICTIM_SIZE 16

int display_victim(heap_ctx_t *ctx, int idx) {
    unsigned char buf[VICTIM_SIZE];
    unsigned long funptr = 0;
    int i, j;

    if (heap_check_ctx(ctx) < 0) {
        return -1;
    }

    for (i = 0; i < VICTIM_SIZE; i++) {
        struct request_arg req;
        req.handler = idx;
        req.offset = i;
        req.value = 0;
        if (ioctl(ctx->fd, IOCTL_READ_VICTIM, &req) < 0) {
            perror("[-] read victim ioctl failed");
            return -1;
        }
        buf[i] = (unsigned char)req.value;
    }

    for (i = 0; i < (int)sizeof(unsigned long); i++) {
        funptr |= ((unsigned long)buf[i]) << (i * 8);
    }

    printf("[*] victim[%d] funptr = 0x%lx\n", idx, funptr);
    printf("[*] victim[%d] content:\n", idx);
    for (i = 0; i < VICTIM_SIZE; i += 16) {
        printf("    %04x:", i);
        for (j = 0; j < 16 && i + j < VICTIM_SIZE; j++) {
            printf(" %02x", buf[i + j]);
        }
        printf("\n");
    }

    return 0;
}

int heap_alloc_dummy(heap_ctx_t *ctx, size_t count, int *out) {
    return heap_alloc(ctx, HEAP_OBJ_DUMMY, count, out);
}

int heap_free_dummy(heap_ctx_t *ctx, int idx) {
    return heap_free(ctx, HEAP_OBJ_DUMMY, idx);
}

int heap_alloc_defrag(heap_ctx_t *ctx, size_t count, int *out) {
    return heap_alloc(ctx, HEAP_OBJ_DEFRAG, count, out);
}

#define DEFRAG_CONSECUTIVE_FRESH 2
#define DEFRAG_MAX_SPRAY         4096

static int parse_objs_per_slab(const char *cache_name, int *objs_per_slab) {
    FILE *fp;
    char line[512];
    char name[128];

    fp = fopen("/proc/slabinfo", "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        int a, t, sz, ops;
        if (line[0] == '#') {
            continue;
        }
        if (sscanf(line, "%127s %d %d %d %d", name, &a, &t, &sz, &ops) != 5) {
            continue;
        }
        if (strcmp(name, cache_name) == 0) {
            *objs_per_slab = ops;
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    return -1;
}

int heap_defrag(heap_ctx_t *ctx, const char *cache_name) {
    int objs_per_slab = 8;
    int prev_verbose;
    int total = 0;
    int fresh_runs = 0;
    int run_length = 0;
    unsigned long current_base = 0;
    int rc = -1;

    if (heap_check_ctx(ctx) < 0) {
        return -1;
    }

    if (cache_name == NULL) {
        errno = EINVAL;
        fprintf(stderr, "[-] cache_name is null\n");
        return -1;
    }

    if (parse_objs_per_slab(cache_name, &objs_per_slab) < 0) {
        fprintf(stderr, "[!] cache '%s' not found in /proc/slabinfo, assuming objs_per_slab=%d\n",
                cache_name, objs_per_slab);
    }

    printf("[*] defrag %s (objs_per_slab=%d): spraying until %d consecutive full-slab runs\n",
           cache_name, objs_per_slab, DEFRAG_CONSECUTIVE_FRESH);

    prev_verbose = heap_verbose;
    heap_verbose = 0;

    while (total < DEFRAG_MAX_SPRAY) {
        int handle = 0;
        unsigned long addr = 0;
        unsigned long base;

        if (heap_alloc_defrag(ctx, 1, &handle) < 0) {
            goto out;
        }
        if (heap_get_addr(ctx, HEAP_OBJ_DEFRAG, handle, &addr) < 0) {
            goto out;
        }
        total++;
        base = addr & ~0xFFFUL;

        if (base == current_base) {
            run_length++;
        } else {
            if (run_length > 0 && run_length < objs_per_slab) {
                fresh_runs = 0;
            }
            current_base = base;
            run_length = 1;
        }

        if (run_length == objs_per_slab) {
            fresh_runs++;
            if (fresh_runs >= DEFRAG_CONSECUTIVE_FRESH) {
                rc = total;
                goto out;
            }
            run_length = 0;
            current_base = 0;
        }
    }

    fprintf(stderr, "[-] defrag failed to converge within %d defrags\n", DEFRAG_MAX_SPRAY);
    errno = EIO;

out:
    heap_verbose = prev_verbose;
    if (rc >= 0) {
        printf("[+] defrag converged after %d defrags (%d consecutive full slabs)\n",
               total, fresh_runs);
    }
    return rc;
}

int heap_get_addr(heap_ctx_t *ctx, int type, int idx, unsigned long *addr) {
    struct addr_arg req;

    if (heap_check_ctx(ctx) < 0) {
        return -1;
    }

    if (addr == NULL) {
        errno = EINVAL;
        fprintf(stderr, "[-] addr output buffer is null\n");
        return -1;
    }

    req.type = type;
    req.handler = idx;
    req.addr = 0;

    if (ioctl(ctx->fd, IOCTL_GET_ADDR, &req) < 0) {
        perror("[-] get_addr ioctl failed");
        return -1;
    }

    *addr = req.addr;
    return 0;
}
