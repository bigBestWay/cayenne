obj-m   := cayenne.o
cayenne-objs := base64.o handler.o main.o
KDIR    := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)
 
all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean