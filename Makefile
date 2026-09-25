# Makefile для модуля myblock
obj-m += myblock.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

.PHONY: all clean load unload reload help

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load: all
	sudo insmod myblock.ko

unload:
	sudo rmmod myblock 

reload: unload load
