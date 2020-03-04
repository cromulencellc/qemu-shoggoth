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

TRITON_SRC_DIR=$(PLUGIN_PARENT_DIR)triton-test
TRITON_BUILD_DIR=$(PLUGIN_BUILD_DIR)triton-test
TRITON_TGT=$(TRITON_BUILD_DIR)/triton-test.so
TRITON_SRC=$(TRITON_SRC_DIR)/triton-test.cpp
TRITON_PATH ?= $(SRC_PATH)/../triton

# This is very specific and may change based on your system
TRITON_CXXFLAGS=$(PLUGIN_CXXFLAGS) -I$(TRITON_PATH)/src/libtriton/includes -std=c++11 -Wno-unknown-pragmas $(shell pkg-config --cflags capstone)
TRITON_LDFLAGS=$(PLUGIN_LDFLAGS) -L$(TRITON_PATH)/build/src/libtriton/ -ltriton -lstdc++ $(shell pkg-config --libs capstone)

$(TRITON_TGT): $(TRITON_SRC)
	@mkdir -p $(TRITON_BUILD_DIR)
	$(CC) -o $@ $(TRITON_SRC) $(TRITON_CXXFLAGS) $(TRITON_LDFLAGS)

.PHONY: triton-test triton-plugin
triton-plugin: $(TRITON_TGT)

ifneq ($(wildcard $(TRITON_PATH)/.*),)
PLUGIN_TARGETS += $(TRITON_TGT)
FOUND_TRITON="y"
endif

triton-test:
ifeq ($(FOUND_TRITON),"y")
	mkdir -p $(TRITON_PATH)/build
	cd $(TRITON_PATH)/build; cmake .. -DCMAKE_BUILD_TYPE=Release
	$(MAKE) -C $(TRITON_PATH)/build
	$(MAKE) -C $(TRITON_SRC_DIR) CC=$(CC) PLUGIN_LDFLAGS="$(PLUGIN_LDFLAGS)" PLUGIN_CXXFLAGS="$(PLUGIN_CXXFLAGS)" PLUGIN_BUILD_DIR=$(PLUGIN_BUILD_DIR) PLUGIN_PARENT_DIR=$(PLUGIN_PARENT_DIR) TRITON_PATH=$(TRITON_PATH) triton-plugin
	@echo 'A plugin can be found here - $(TRITON_TGT)'
else
	@echo 'Triton not found - skipping triton-test plugin'
endif
