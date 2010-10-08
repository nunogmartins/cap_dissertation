obj-m    := experiment.o other.o

experiment-y	:= exp.o instrument.o



KDIR    := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)
INCLUDE:= /usr/src/linux-headers-$(shell uname -r)/include/

default: 
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm *.o *.mod.* *.ko 
