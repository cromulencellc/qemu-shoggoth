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

HELLO_CXX_SRC_DIR=$(PLUGIN_PARENT_DIR)hello-cpp
HELLO_CXX_BUILD_DIR=$(PLUGIN_BUILD_DIR)hello-cpp
HELLO_CXX_TGT=$(HELLO_CXX_BUILD_DIR)/hello-cpp.so
PLUGIN_TARGETS += $(HELLO_CXX_TGT)

hello_cxx-obj-y = $(HELLO_CXX_BUILD_DIR)/hello-cpp.o $(HELLO_CXX_BUILD_DIR)/printer.o

$(HELLO_CXX_BUILD_DIR)/%.o: $(HELLO_CXX_SRC_DIR)/%.cpp
	@mkdir -p $(HELLO_CXX_BUILD_DIR)
	$(CXX) -g -c $(PLUGIN_CXXFLAGS) -std=c++11 $< -o $@

$(HELLO_CXX_TGT): $(hello_cxx-obj-y)
	$(CXX) -g -o $@ $^ $(PLUGIN_CXXFLAGS) $(PLUGIN_LDFLAGS) -std=c++11

.PHONY: hello-cpp
hello-cpp: $(HELLO_CXX_TGT)
	@echo 'A plugin can be found here - $(HELLO_CXX_TGT)'
