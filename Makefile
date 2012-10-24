#
# Makefile for the linux ext3301-filesystem routines.
#

obj-m += ext3301.o

ext3301-y := acl.o balloc.o dir.o file.o ialloc.o inode.o \
	  ioctl.o namei.o super.o symlink.o  \
	  xattr.o xattr_user.o xattr_trusted.o xattr_security.o

MOD_DIR=/lib/modules/$(shell uname -r)/build

.PHONY: all
all:
	make -C $(MOD_DIR) M=$(PWD) modules

.PHONY: clean
clean:
	make -C $(MOD_DIR) M=$(PWD) clean
