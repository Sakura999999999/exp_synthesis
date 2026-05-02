# 堆工具使用说明

该工具旨在帮助你在玩具环境上查看堆分配情况，进而进行漏洞复现。

目前 heap_api.* 中一系列调用的实现仍基于原来的玩具环境，因此需要加载一个内核模块到内核中，以包含 heap_api.c 开头给出的一系列 IOCTL_* 定义。为此，我上传了一个示例的内核模块 oob_heapfengshui.c，以及两个用户态的漏洞利用文件 exp.c, exp_random.c (前者没考虑 slab 队列随机化，后者考虑了)。

注意：上述提到的内核模块和 heap_api.* 中的一些定义（如各个对象的定义）完全可以进行修改，以符合你所要复现的漏洞类型、obj_size 等。

整个堆工具可以分为两部分：

- heap_api.* 中定义的各个接口的调用，如堆分配以及释放等
- analyze_slabinfo.py 允许查看特定内存地址的内容以相应 slab 的分配情况，但需要安装 pwndbg 工具。

## 调用 heap api 的方法

各个 heap api 的具体调用可直接查阅 heap_api.h，我做了详细注释。或查看 exp.c / exp_random.c，里面有示例。

```bash
# 在 host 对应目录中编译内核模块
# 可能需要根据实际环境修改 Makefile 中的 KERNEL_PATH
make

# 在 guest 中加载内核模块
sudo insmod oob_heapfengshui.ko
# 在 guest 中编译用户态漏洞利用与 heap_api
make user
# 执行漏洞利用程序
sudo ./exp

# 清理所有的内核模块和用户态程序文件
make clean
```

## 查看 slab 分配情况

### 安装 pwndbg:

```bash
git clone git@github.com:pwndbg/pwndbg.git
cd pwndbg
./setup.sh
```

在调试过程中，如果想要看进行某一操作后各个 obj 的分配情况，那么进行如下操作即可：

### 在 host 中进行远程 gdb

```bash
gdb Kernel/v5.13/x86_64/vmlinux # 你的 guest 对应的 vmlinux 的路径
pwndbg> target remote :1234
```

### 获取调试信息并进行分析

```bash
# eg. kmalloc-512
pwndbg> slab info -v kmalloc-512
```

然后将输出复制到 log.txt 中。接着运行 analyze_slabinfo.py 进行统计。

```bash
# 统计 slab 信息
python3 analyze_slabinfo.py

# 查看某一特定地址的 slab 信息（freelist等）
python3 analyze_slabinfo.py 0xffff888107f68000
```