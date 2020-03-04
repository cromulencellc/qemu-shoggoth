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

PYTHON=python3
PWNME_LITTLE_TGT=$(PLUGIN_PARENT_DIR)pwnme_little_bof/pwnme_little_bof.pyc
PWNME_LITTLE_SRC=$(PLUGIN_PARENT_DIR)pwnme_little_bof/pwnme_little_bof.py
PLUGIN_TARGETS += $(PWNME_LITTLE_TGT)

.PHONY: pwnme_little_bof

# At the minimum, you need a recipe that matches the directory
# name. This resides in a folder named hello-world so:
pwnme_little_bof:
	@$(PYTHON) -m compileall -b $(PWNME_LITTLE_SRC)
	@echo 'A plugin can be found here - $(PWNME_LITTLE_TGT)'
