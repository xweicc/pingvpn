
obj-m := pingvpn.o

CONFIG_MODULE_SIG=n
EXTRA_CFLAGS = -g -O0

CC=gcc
BULID_PATH=/lib/modules/$(shell uname -r)/build


all:clean module pvpn

module:
	make -C $(BULID_PATH) M=$(PWD) modules

clean:
	make -C $(BULID_PATH) M=$(PWD) clean
	rm -rf *.o pvpn

pvpn:
	$(CC) pvpn.c -o pvpn -Wall

