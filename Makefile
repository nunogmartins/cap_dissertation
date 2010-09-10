obj-m    := exp.o kprobe_example.o

KDIR    := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)
EXTRA_CFLAGS := -Wall

default:
	$(MAKE) $(CFLAGS) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm exp.o exp.mod.* exp.ko kprobe_example.o kprobe_example.mod.* kprobe_example.ko
