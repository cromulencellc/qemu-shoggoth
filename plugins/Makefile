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

# Collect directories
PLUGIN_PARENT_DIR=$(SRC_PATH)/plugins/
PLUGIN_BUILD_DIR=$(BUILD_DIR)/plugin_build/
PLUGIN_ARTIFACTS_DIRS=
PLUGIN_DIRS=$(sort $(dir $(wildcard $(SRC_PATH)/plugins/*/.)))
PLUGIN_TARGETS=
MAKE ?= make

# Remove unwanted flags
PLUGIN_CFLAGS := $(filter-out -fPIE, $(QEMU_CFLAGS))
PLUGIN_CFLAGS := $(filter-out -DPIE, $(PLUGIN_CFLAGS))
PLUGIN_CFLAGS := -I$(SRC_PATH)/include -I$(SRC_PATH) -I$(BUILD_DIR) -fPIC $(PLUGIN_CFLAGS)
PLUGIN_CXXFLAGS := $(filter-out -fPIE, $(QEMU_CXXFLAGS))
PLUGIN_CXXFLAGS := $(filter-out -DPIE, $(PLUGIN_CXXFLAGS))
PLUGIN_CXXFLAGS := -I$(SRC_PATH)/include/cpp -I$(SRC_PATH)/include -I$(SRC_PATH) -I$(BUILD_DIR) -fPIC $(PLUGIN_CXXFLAGS)

# Compiler Settings that are suggested to use in subdirectories
PLUGIN_LDFLAGS=-shared -fPIC

include $(PLUGIN_PARENT_DIR)/qapi-gen.mak

# Include makefiles from subdirectories and build a target
# list from the subdirectories
include $(addsuffix Makefile, $(PLUGIN_DIRS))
all_pls=$(patsubst $(PLUGIN_PARENT_DIR)%/,%,$(dir $(PLUGIN_DIRS)))

.PHONY: plugins plugins_install

# Build everything
plugins: $(all_pls) plugins_install

# Build all targets that are also a subdirectory
$(all_pls):

plugins_install: $(all_pls) 
	@echo "Installing $(PLUGIN_TARGETS) to $(qemu_plugindir)"
	@mkdir -p $(qemu_plugindir)
	@install -m 644 $(PLUGIN_TARGETS) $(qemu_plugindir)

plugins_clean:
	@rm -rf $(PLUGIN_BUILD_DIR)
ifneq ($(PLUGIN_ARTIFACTS_DIRS),)
	@rm -Rf $(PLUGIN_ARTIFACTS_DIRS)
endif
