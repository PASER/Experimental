obj-m :=	rom.o
rom-y := 	main.o \
		queue.o \
		nfhook.o \
		netlink.o \
		table.o \
		llf.o \

ccflags-y := -Wall -g

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
