obj-m:=CCModule.o
CCModule-objs   :=sdthook.o syscalltable.o netlinkp.o 
KDIR   := /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	$(RM) -rf .*.cmd *.mod.c *.o *.ko .tmp*

