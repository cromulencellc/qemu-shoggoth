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
# *  Daniel Reyes
# *
# * This work is licensed under the terms of the GNU GPL, version 2 or later.
# * See the COPYING file in the top-level directory.
# * 
# * The creation of this code was funded by the US Government.
# */

AFL_PLUGIN_SRC_DIR=$(PLUGIN_PARENT_DIR)afl-plugin
AFL_PLUGIN_BUILD_DIR=$(PLUGIN_BUILD_DIR)afl-plugin
AFL_PLUGIN_TGT=$(AFL_PLUGIN_BUILD_DIR)/afl-plugin.so
PLUGIN_TARGETS += $(AFL_PLUGIN_TGT)

afl-obj-y = $(AFL_PLUGIN_BUILD_DIR)/afl-plugin.o

$(AFL_PLUGIN_BUILD_DIR)/%.o: $(AFL_PLUGIN_SRC_DIR)/%.c
	@mkdir -p $(AFL_PLUGIN_BUILD_DIR)
	$(CC) -g -c $(PLUGIN_CFLAGS) $< -o $@

$(AFL_PLUGIN_TGT): $(afl-obj-y)
	$(CC) -o $@ $^ $(PLUGIN_CFLAGS) $(PLUGIN_LDFLAGS)

# At the minimum, you need a recipe that matches the directory
# name. This resides in a folder named hello-world so:
.PHONY: afl-plugin
afl-plugin: $(AFL_PLUGIN_TGT)
	@echo 'A plugin can be found here - $(AFL_PLUGIN_TGT)'
