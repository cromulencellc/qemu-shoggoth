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

PYPL_SRC_DIR=$(PLUGIN_PARENT_DIR)python-interface
PYPL_BUILD_DIR=$(PLUGIN_BUILD_DIR)python-interface
PYPL_GEN_DIR=$(PYPL_BUILD_DIR)/gen

PYTHON_TGT = $(PYPL_BUILD_DIR)/python-interface.so
python_obj = $(PYPL_BUILD_DIR)/python-interface.o
PLUGIN_TARGETS += $(PYTHON_TGT)

# Try to find python for Debian or Red Hat
PYTHON_VER=$(shell if pkg-config --exists python3; then echo "python3"; else echo "python-3.4"; fi)
PYTHON_INTERFACE_CFLAGS=$(PLUGIN_CFLAGS)  $(shell pkg-config --cflags "$(PYTHON_VER)") -I $(PYPL_GEN_DIR)
PYTHON_PKGCFG=$(shell pkg-config --libs "$(PYTHON_VER)")
# Try to find python libs for 3.7 and below or 3.8 and above 
PYTHON_LIBS=$(shell if test -z "$(PYTHON_PKGCFG)"; then python3-config --libs --embed; else echo "$(PYTHON_PKGCFG)"; fi)
PYTHON_INTERFACE_LDFLAGS=$(PLUGIN_LDFLAGS) $(PYTHON_LIBS)

# This inserts rules to generate/compile the QAPI defined in example.json
$(eval $(call qapi-gen,python,$(PYPL_SRC_DIR)/python.json,$(PYPL_GEN_DIR)))

# Compiles our API
$(PYPL_BUILD_DIR)/%.o: $(PYPL_SRC_DIR)/%.c
	$(call quiet-command,\
		$(CC) -g -c $(PYTHON_INTERFACE_CFLAGS) $< -o $@\
		,"CC","$<")

# Generates the plugin .so file
$(PYTHON_TGT): $(python_obj) $(python-interface-obj-y)
	$(call quiet-command,\
		$(CC) -g -o $@ $^ $(PYTHON_INTERFACE_LDFLAGS)\
		,"PLUGIN","$@")

.PHONY: python-interface
python-interface: $(PYTHON_TGT)
	@echo 'A plugin can be found here - $(PYTHON_TGT)'
	-@cd $(PYPL_SRC_DIR); \
		python3 setup.py sdist bdist_wheel; \
		python3 -m pip install --force-reinstall --user dist/pyqemu-0.1-py3-none-any.whl
