obj-m    := exp.o

KDIR    := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)
INCLUDE:= /usr/src/linux-headers-$(shell uname -r)/include/

default: 
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm exp.o exp.mod.* exp.ko 
