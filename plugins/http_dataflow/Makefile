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

HTTP_DATAFLOW_SRC_DIR=$(PLUGIN_PARENT_DIR)http_dataflow
HTTP_DATAFLOW_BUILD_DIR=$(PLUGIN_BUILD_DIR)http_dataflow
HTTP_DATAFLOW_TGT=$(HTTP_DATAFLOW_BUILD_DIR)/http_dataflow.so
PLUGIN_TARGETS += $(HTTP_DATAFLOW_TGT)

http_dataflow-obj-y = $(HTTP_DATAFLOW_BUILD_DIR)/http_dataflow.o

$(HTTP_DATAFLOW_BUILD_DIR)/%.o: $(HTTP_DATAFLOW_SRC_DIR)/%.c
	@mkdir -p $(HTTP_DATAFLOW_BUILD_DIR)
	$(CC) -g -c $(PLUGIN_CFLAGS) $< -o $@

$(HTTP_DATAFLOW_TGT): $(http_dataflow-obj-y)
	$(CC) -o $@ $^ $(PLUGIN_CFLAGS) $(PLUGIN_LDFLAGS)

# At the minimum, you need a recipe that matches the directory
# name. This resides in a folder named http_dataflow so:
.PHONY: http_dataflow
http_dataflow: $(HTTP_DATAFLOW_TGT)
	@echo 'A plugin can be found here - $(HTTP_DATAFLOW_TGT)'
