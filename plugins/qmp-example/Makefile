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

QMPX_SRC_DIR=$(PLUGIN_PARENT_DIR)qmp-example
QMPX_BUILD_DIR=$(PLUGIN_BUILD_DIR)qmp-example
QMPX_GEN_DIR=$(QMPX_BUILD_DIR)/gen
QMPX_TGT = $(QMPX_BUILD_DIR)/qmp-example.so
PLUGIN_TARGETS += $(QMPX_TGT)

QMPX_CFLAGS=$(PLUGIN_CFLAGS) -I$(QMPX_GEN_DIR)

qmpx_obj = $(QMPX_BUILD_DIR)/qmp-example.o

# This inserts rules to generate/compile the QAPI defined in example.json
$(eval $(call qapi-gen,example,$(QMPX_SRC_DIR)/example.json,$(QMPX_GEN_DIR)))

# Compiles our API
$(QMPX_BUILD_DIR)/%.o: $(QMPX_SRC_DIR)/%.c
	$(call quiet-command,\
		$(CC) -g -c $(QMPX_CFLAGS) $< -o $@\
		,"CC","$<")

# Generates the plugin .so file
$(QMPX_TGT): $(QMPX_BUILD_DIR)/qmp-example.o $(example-interface-obj-y)
	$(call quiet-command,\
		$(CC) -g -o $@ $^ $(PLUGIN_LDFLAGS)\
		,"PLUGIN","$@")

# Copies the plugin to an output folder
.PHONY: qmp-example
qmp-example: $(QMPX_TGT)
	@echo 'A plugin can be found here - $(QMPX_TGT)'
