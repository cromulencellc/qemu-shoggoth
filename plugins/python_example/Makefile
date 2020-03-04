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
PYEXAMPLE_TGT=$(PLUGIN_PARENT_DIR)python_example/example.pyc
PYEXAMPLE_SRC=$(PLUGIN_PARENT_DIR)python_example/example.py
PLUGIN_TARGETS += $(PYEXAMPLE_TGT)

.PHONY: python_example

# At the minimum, you need a recipe that matches the directory
# name. This resides in a folder named hello-world so:
python_example:
	@$(PYTHON) -m compileall -b $(PYEXAMPLE_SRC)
	@echo 'A plugin can be found here - $(PYEXAMPLE_TGT)'
