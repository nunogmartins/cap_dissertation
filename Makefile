obj-m	:=monitoring_syscalls.o
#obj-m	:=monitoring_syscalls.o monitoring_calls.o
#obj-m    := experiment.o other.o jprobe.o instrumentation.o my_module.o

#experiment-y	:= exp.o

#instrumentation-y	:=instrument.o ports_table.o

#my_module-y	:=monitor_tcp_udp.o debugfs_support.o ports_table.o

#my_module-y	:=monitor.o common_monitor_func.o tcp_monitor_func.o udp_monitor_func.o debugfs_support.o ports_table.o

monitoring_syscalls-y	:=monitor.o syscalls_monitor.o debugfs_support.o table_port.o filter.o tools.o portsDB.o unit_tests.o

#monitoring_calls-y	:=monitor.o common_monitor_func.o tcp_monitor_func.o udp_monitor_func.o debugfs_support.o ports_table.o

KDIR    := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)

#KDIR	:=/home/nuno/linux_source
all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

default: 
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
