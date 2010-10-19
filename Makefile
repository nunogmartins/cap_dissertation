obj-m    := experiment.o other.o jprobe.o instrumentation.o my_module.o

experiment-y	:= exp.o

instrumentation-y	:=instrument.o ports_table.o

my_module-y	:=instrument_module.o

KDIR    := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)

default: 
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
