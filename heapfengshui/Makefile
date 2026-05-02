obj-m := oob_heapfengshui.o

EXTRA_CFLAGS += -g -O0

CC ?= gcc
USER_CFLAGS ?= -Wall -Wextra -g -O0
USER_BINS := exp_random exp
USER_OBJS := exp_random.o exp.o heap_api.o

CURRENT_PATH := $(shell pwd)
# 你需要根据实际环境修改内核路径
KERNEL_PATH ?= $(HOME)/Kernel/v5.13/x86_64

all:
	make -C $(KERNEL_PATH) M=$(CURRENT_PATH) modules

user: $(USER_BINS)

exp_random: exp_random.o heap_api.o
	$(CC) $(USER_CFLAGS) -o $@ exp_random.o heap_api.o

exp: exp.o heap_api.o
	$(CC) $(USER_CFLAGS) -o $@ exp.o heap_api.o

exp_random.o: exp_random.c heap_api.h
	$(CC) $(USER_CFLAGS) -c -o $@ exp_random.c

exp.o: exp.c heap_api.h
	$(CC) $(USER_CFLAGS) -c -o $@ exp.c

heap_api.o: heap_api.c heap_api.h
	$(CC) $(USER_CFLAGS) -c -o $@ heap_api.c

clean:
	make -C $(KERNEL_PATH) M=$(CURRENT_PATH) clean
	rm -f $(USER_BINS) $(USER_OBJS)

.PHONY: all clean user
