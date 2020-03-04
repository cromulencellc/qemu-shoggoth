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
# *  Joseph Walker
# *
# * This work is licensed under the terms of the GNU GPL, version 2 or later.
# * See the COPYING file in the top-level directory.
# * 
# * The creation of this code was funded by the US Government.
# */

HELLO_SRC_DIR=$(PLUGIN_PARENT_DIR)hello-world
HELLO_BUILD_DIR=$(PLUGIN_BUILD_DIR)hello-world
HELLO_TGT=$(HELLO_BUILD_DIR)/hello-world.so
PLUGIN_TARGETS += $(HELLO_TGT)

hello-obj-y = $(HELLO_BUILD_DIR)/hello-world.o

$(HELLO_BUILD_DIR)/%.o: $(HELLO_SRC_DIR)/%.c
	@mkdir -p $(HELLO_BUILD_DIR)
	$(CC) -g -c $(PLUGIN_CFLAGS) $< -o $@

$(HELLO_TGT): $(hello-obj-y)
	$(CC) -o $@ $^ $(PLUGIN_CFLAGS) $(PLUGIN_LDFLAGS)

# At the minimum, you need a recipe that matches the directory
# name. This resides in a folder named hello-world so:
.PHONY: hello-world
hello-world: $(HELLO_TGT)
	@echo 'A plugin can be found here - $(HELLO_TGT)'
