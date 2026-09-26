DRV_NAME := kuzdriver
DEV_NAME := KuzEncDev
obj-m += $(DRV_NAME).o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
CC   ?= gcc

.PHONY: all module test clean load unload reload help

all: module test_ioctl

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

test: load
	sudo dd if=/dev/urandom of=/dev/$(DEV_NAME)0 bs=4k count=10
	sudo ./test_ioctl /dev/$(DEV_NAME)0 | grep -E "reads|writes|bytes"

test_ioctl: test_ioctl.c $(DRV_NAME)_ioctl.h
	$(CC) -Wall -O2 -o $@ $<

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f test_ioctl

load: module
	sudo insmod $(DRV_NAME).ko

unload:
	sudo rmmod $(DRV_NAME).ko

reload: unload load

format:
	clang-format -i *.c *.h