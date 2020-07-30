obj-m += hvc.o

ccflags-y := -std=gnu99 -Wno-declaration-after-statement

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	$(CC) hvc_test.c -o hvc_test

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm hvc_test
