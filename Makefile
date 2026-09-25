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
	@echo "--- dmesg ---"
	@sudo dmesg | tail -n 5

unload:
	sudo rmmod myblock || true
	@echo "--- dmesg ---"
	@sudo dmesg | tail -n 5

reload: unload load

help:
	@echo "Доступные цели:"
	@echo "  all     - собрать модуль"
	@echo "  clean   - очистить артефакты сборки"
	@echo "  load    - загрузить модуль (insmod)"
	@echo "  unload  - выгрузить модуль (rmmod)"
	@echo "  reload  - unload + load"