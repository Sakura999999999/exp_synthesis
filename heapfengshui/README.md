1. 添加 oob_heapfengshui 内核模块
2. 在 guest 中编译 manage_heap.c
3. 在 host 中启动 GDB 并连接，开始调试（具体调试命令见 manage_heap.c）：
* guest 中：
```bash
./manage_heap alloc_vul 100
./manage_heap free_vul 3
```
* host 中：
```bash
slab info kmalloc-512 -v
```
