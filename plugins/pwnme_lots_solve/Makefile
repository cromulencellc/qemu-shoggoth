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

PWNME_LOTS_SOLVE_SRC_DIR=$(PLUGIN_PARENT_DIR)pwnme_lots_solve
PWNME_LOTS_SOLVE_BUILD_DIR=$(PLUGIN_BUILD_DIR)pwnme_lots_solve
PWNME_LOTS_SOLVE_TGT=$(PWNME_LOTS_SOLVE_BUILD_DIR)/pwnme_lots_solve.so
PLUGIN_TARGETS += $(PWNME_LOTS_SOLVE_TGT)

pwnme_lots_solve-obj-y = $(PWNME_LOTS_SOLVE_BUILD_DIR)/pwnme_lots_solve.o

$(PWNME_LOTS_SOLVE_BUILD_DIR)/%.o: $(PWNME_LOTS_SOLVE_SRC_DIR)/%.c
	@mkdir -p $(PWNME_LOTS_SOLVE_BUILD_DIR)
	$(CC) -g -c $(PLUGIN_CFLAGS) $< -o $@

$(PWNME_LOTS_SOLVE_TGT): $(pwnme_lots_solve-obj-y)
	$(CC) -g -o $@ $^ $(PLUGIN_CFLAGS) $(PLUGIN_LDFLAGS)

.PHONY: pwnme_lots_solve
pwnme_lots_solve: $(PWNME_LOTS_SOLVE_TGT)
	@echo 'A plugin can be found here - $(PWNME_LOTS_SOLVE_TGT)'
