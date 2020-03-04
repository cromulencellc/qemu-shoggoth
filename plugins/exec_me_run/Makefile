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

EXEC_ME_RUN_SRC_DIR=$(PLUGIN_PARENT_DIR)exec_me_run
EXEC_ME_RUN_BUILD_DIR=$(PLUGIN_BUILD_DIR)exec_me_run
EXEC_ME_RUN_TGT=$(EXEC_ME_RUN_BUILD_DIR)/exec_me_run.so
PLUGIN_TARGETS += $(EXEC_ME_RUN_TGT)

exec_me_run-obj-y = $(EXEC_ME_RUN_BUILD_DIR)/exec_me_run.o

$(EXEC_ME_RUN_BUILD_DIR)/%.o: $(EXEC_ME_RUN_SRC_DIR)/%.c
	@mkdir -p $(EXEC_ME_RUN_BUILD_DIR)
	$(CC) -g -c $(PLUGIN_CFLAGS) $< -o $@

$(EXEC_ME_RUN_TGT): $(exec_me_run-obj-y)
	$(CC) -g -o $@ $^ $(PLUGIN_CFLAGS) $(PLUGIN_LDFLAGS)

.PHONY: exec_me_run
exec_me_run: $(EXEC_ME_RUN_TGT)
	@echo 'A plugin can be found here - $(EXEC_ME_RUN_TGT)'
