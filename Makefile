obj-m    := experiment.o other.o jprobe.o instrumentation.o

experiment-y	:= exp.o

instrumentation-y	:=instrument.o ports_table.o


KDIR    := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)

default: 
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
