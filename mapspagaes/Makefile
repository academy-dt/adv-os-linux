KDIR ?= ..

NAME = mapspages
EXTRA_CFLAGS = -Wall -g
obj-m = $(NAME).o

kbuild:
	make -C $(KDIR) M=$(PWD) modules

install:
	cp $(NAME).ko /lib/modules/$(shell uname -r)/
	depmod

uninstall:
	rm /lib/modules/$(shell uname -r)/$(NAME).ko
	depmod

clean:
	make -C $(KDIR) M=$(PWD) clean
