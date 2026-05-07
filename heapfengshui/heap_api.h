#ifndef HEAP_API_H
#define HEAP_API_H

#include <stddef.h>

/* 堆设备默认路径，需自行修改 */
#define HEAP_DEFAULT_DEVICE "/dev/uv_oob_dev"

/* 对象类型定义 */
#define HEAP_OBJ_VUL    0
#define HEAP_OBJ_VICTIM 1
#define HEAP_OBJ_DUMMY  2  // 类似 spray_obj
#define HEAP_OBJ_DEFRAG 3  // 去碎片化时分配的 defrag 对象，没有别的用处

/* 分配多个 vul 对象 
 * 部分参数：
 * count: 分配数量
 * out: 输出对象索引
 * eg. heap_alloc_vul(fd, 1, &vulobj_idx); 
 */
int heap_alloc_vul(int fd, size_t count, int *out);

/* 释放 vul[idx] 对象 
 * 部分参数：
 * idx: 对象索引
 * eg. heap_free_vul(fd, 10); 
 */
int heap_free_vul(int fd, int idx);

/* 写入 vul[idx] 对象  
 * 部分参数：
 * idx: 对象索引
 * offset: 偏移量
 * value: 写入值
 * eg. heap_write_vul(fd, 10, 0, 'A'); 
 */
int heap_write_vul(int fd, int idx, int offset, char value);

/* 分配 victim 对象 */
int heap_alloc_victim(int fd, size_t count, int *out);

/* 释放 victim 对象 */
int heap_free_victim(int fd, int idx);

/* 显示 victim[idx] 的内容 
 * 部分参数：
 * idx: 对象索引
 * eg. heap_read_victim(fd, 10); 
 */
int heap_read_victim(int fd, int idx);

/* 这里我定义的 victim 对象头部有一个 void (*funptr)(void); 的函数指针；
 * 该函数会执行对应的函数（见 oob_heapfengshui.c 中的 uv_victim 结构体定义）
 * 部分参数：
 * idx: 对象索引
 * eg. heap_execute_victim(fd, 10); 
 */
 int heap_execute_victim(int fd, int idx);

/* 分配 dummy 对象 */
int heap_alloc_dummy(int fd, size_t count, int *out);

/* 释放 dummy 对象 */
int heap_free_dummy(int fd, int idx);

/* 获取对象地址 
 * 部分参数：
 * type: 对象类型
 * idx: 对象索引
 * addr: 输出的地址
 * eg. heap_get_addr(fd, HEAP_OBJ_VUL, 10, &addr); 
 */
int heap_get_addr(int fd, int type, int idx, unsigned long *addr);

/* 分配 defrag 对象 */
int heap_alloc_defrag(int fd, size_t count, int *out);

/* 去碎片化 
 * eg. heap_defrag(fd); 
 */
int heap_defrag(int fd);

#endif
