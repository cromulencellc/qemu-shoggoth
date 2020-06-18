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
TRACEEXECME_TGT=$(PLUGIN_PARENT_DIR)trace_exec_me/trace_exec_me.pyc
TRACEEXECME_SRC=$(PLUGIN_PARENT_DIR)trace_exec_me/trace_exec_me.py
PLUGIN_TARGETS += $(TRACEEXECME_TGT)

.PHONY: trace_exec_me

# At the minimum, you need a recipe that matches the directory
# name. This resides in a folder named hello-world so:
trace_exec_me:
	@$(PYTHON) -m compileall -b $(TRACEEXECME_SRC)
	@echo 'A plugin can be found here - $(TRACEEXECME_TGT)'
