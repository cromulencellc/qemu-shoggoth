#/*
# * Rapid Analysis QEMU System Emulator
# *
# * Copyright (c) 2020 Cromulence LLC
# *
# * Distribution Statement A
# *
# * Approved for Public Release, Distribution Unlimited
# *
# * Authors:
# *  Adam Critchley
# *
# * This work is licensed under the terms of the GNU GPL, version 2 or later.
# * See the COPYING file in the top-level directory.
# * 
# * The creation of this code was funded by the US Government.
# */

OS_LINUX_SRC_DIR=$(PLUGIN_PARENT_DIR)os-linux
OS_LINUX_BUILD_DIR=$(PLUGIN_BUILD_DIR)os-linux
OS_LINUX_TGT=$(OS_LINUX_BUILD_DIR)/os-linux.so
OS_LINUX_SRC=$(OS_LINUX_SRC_DIR)/os-linux.c
PLUGIN_TARGETS += $(OS_LINUX_TGT)

os_linux-obj-y = $(OS_LINUX_BUILD_DIR)/os-linux.o

$(OS_LINUX_BUILD_DIR)/%.o: $(OS_LINUX_SRC_DIR)/%.c x86_64-softmmu/config-target.h
	@mkdir -p $(OS_LINUX_BUILD_DIR)
	$(CC) -ggdb -c $(PLUGIN_CFLAGS) -I$(SRC_PATH) -I$(SRC_PATH)/tcg -I$(SRC_PATH)/tcg/i386 -I$(SRC_PATH)/target/i386 -I$(BUILD_DIR)/x86_64-softmmu -DNEED_CPU_H $< -o $@

$(OS_LINUX_TGT): $(os_linux-obj-y)
	$(CC) -o $@ $^ $(PLUGIN_CFLAGS) $(PLUGIN_LDFLAGS)

.PHONY: os-linux
os-linux: $(OS_LINUX_TGT)
	@echo 'A plugin can be found here - $(OS_LINUX_TGT)'
