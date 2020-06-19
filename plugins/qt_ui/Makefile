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
# * The creation of this code was funded by the US Government. Use of this code for any
# * purpose other than those authorized by the funding US Government may be subject to restrictions.
# * 
# * Neither party is granted any right or license other than the existing licenses
# * and covenants expressly stated herein. Cromulence LLC retains all right, title and interest to
# * Reference Code and Technology Specifications and You retain all right, title and interest
# * in Your Modifications and associated specifications as permitted by the existing license.
# * Except as expressly permitted herein, You must not otherwise use any package, class or
# * interface naming conventions that appear to originate from Original Contributor.
# */

# Set up the base directories
QTUI_NAME=qt_ui
QTUI_CXX_SRC_DIR=$(PLUGIN_PARENT_DIR)$(QTUI_NAME)/src
QTUI_CXX_RES_DIR=$(PLUGIN_PARENT_DIR)$(QTUI_NAME)/res
QTUI_CXX_OBJ_DIR=$(PLUGIN_PARENT_DIR)$(QTUI_NAME)/obj
QTUI_CXX_INC_DIR=$(PLUGIN_PARENT_DIR)$(QTUI_NAME)/include
QTUI_CXX_MOC_INC_DIR=$(QTUI_CXX_INC_DIR)/meta
QTUI_CXX_MOC_SRC_DIR=$(QTUI_CXX_SRC_DIR)/moc
QTUI_CXX_RES_SRC_DIR=$(QTUI_CXX_SRC_DIR)/res
QTUI_CXX_BUILD_DIR=$(PLUGIN_BUILD_DIR)$(QTUI_NAME)
QTUI_CXX_TGT=$(QTUI_CXX_BUILD_DIR)/$(QTUI_NAME).so

# Find QT paths
QT_DEPS=Qt5Core Qt5Gui Qt5Widgets Qt5Xml
QT_DIST_INCLUDES=$(shell pkg-config --cflags-only-I $(QT_DEPS)) 

QT_DIST_SYS_INCLUDES=$(patsubst -I%, -isystem %, $(QT_DIST_INCLUDES))
QT_SYS_LIBS=$(shell pkg-config --libs $(QT_DEPS))
QT_SYS_RES=$(shell which rcc)
QT_SYS_MOC=$(shell which moc)

# Build Tools
MOC_CMD:=$(QT_SYS_MOC)
RES_CMD:=$(QT_SYS_RES)

# Build moc lists
MOC_HEADERS:=$(wildcard $(QTUI_CXX_MOC_INC_DIR)/*.h)
MOC_SOURCES:=$(patsubst $(QTUI_CXX_MOC_INC_DIR)/%.h,$(QTUI_CXX_MOC_SRC_DIR)/moc_%.cpp,$(MOC_HEADERS))

# Build resource lists
RES_FILES:=$(wildcard $(QTUI_CXX_RES_DIR)/*.qrc)
RES_SOURCES:=$(patsubst $(QTUI_CXX_RES_DIR)/%.qrc,$(QTUI_CXX_RES_SRC_DIR)/%.cpp,$(RES_FILES))

# Build source/object lists
SOURCE_LIST:=$(MOC_SOURCES) $(RES_SOURCES) $(wildcard $(QTUI_CXX_SRC_DIR)/*.cpp)
OBJECT_LIST:=$(patsubst $(QTUI_CXX_SRC_DIR)%.cpp,$(QTUI_CXX_OBJ_DIR)%.o,$(SOURCE_LIST))

# We need these directories to be created
INTERNAL_DIRS:=$(sort $(dir $(MOC_SOURCES))) $(sort $(dir $(RES_SOURCES))) $(sort $(dir $(OBJECT_LIST)))
ADDED_DIRS:=$(INTERNAL_DIRS) $(QTUI_CXX_BUILD_DIR)

# Pixman is required by the callback code
PIXMAN_CPPFLAGS:=$(shell pkg-config --cflags pixman-1)
PIXMAN_LDFLAGS:=$(shell pkg-config --libs pixman-1)

# Build variables 
QTUI_DEFINES:=-DQT_DEPRECATED_WARNINGS -DQT_NO_DEBUG -DQT_WIDGETS_LIB -DQT_GUI_LIB -DQT_CORE_LIB
QTUI_INCLUDE_PATHS:=-I$(QTUI_CXX_INC_DIR) -I$(QTUI_CXX_MOC_INC_DIR)
QT_INCLUDE_PATHS:=-I/usr/include $(QT_DIST_SYS_INCLUDES)
QTUI_CPPFLAGS:=$(PLUGIN_CXXFLAGS) -pipe -O2 -Wall -W -D_REENTRANT -fPIC $(QTUI_DEFINES) -g -std=c++11 -Wno-unused-variable $(PIXMAN_CPPFLAGS)
QTUI_LDFLAGS:=$(PLUGIN_LDFLAGS) -Wl,-O1 $(PIXMAN_LDFLAGS)
QT_LIBS:=-lGL -lpthread -lstdc++ $(QT_SYS_LIBS)

# Add .o files to this list
qt_ui_cxx-obj-y = $(OBJECT_LIST)
PLUGIN_ARTIFACTS_DIRS+=$(ADDED_DIRS)

.PHONY: qt_ui qt_ui-plugin
qt_ui-plugin: $(QTUI_CXX_TGT)

$(QTUI_CXX_TGT): $(qt_ui_cxx-obj-y)
	@$(CXX) -o $@ $^ $(QTUI_CPPFLAGS) $(QTUI_LDFLAGS) $(QT_LIBS)

$(QTUI_CXX_OBJ_DIR)/%.o: $(QTUI_CXX_SRC_DIR)/%.cpp $(MOC_SOURCES) $(RES_SOURCES) | $(ADDED_DIRS)
	@$(CXX) $(QTUI_CPPFLAGS)  $(QTUI_INCLUDE_PATHS) $(QT_INCLUDE_PATHS) $(SDL_INCLUDE_PATHS) -c $< -o $@

$(QTUI_CXX_RES_SRC_DIR)/%.cpp: $(QTUI_CXX_RES_DIR)/%.qrc | $(ADDED_DIRS)
	@$(RES_CMD) $< -o $@

$(QTUI_CXX_MOC_SRC_DIR)/moc_%.cpp: $(QTUI_CXX_MOC_INC_DIR)/%.h | $(ADDED_DIRS)
	@$(MOC_CMD) $< -o $@

$(ADDED_DIRS):
	mkdir $@

ifneq ($(QT_SYS_MOC),)
ifneq ($(QT_SYS_RES),)
PLUGIN_TARGETS += $(QTUI_CXX_TGT)
endif
endif

qt_ui:
ifneq ($(QT_SYS_MOC),)
ifneq ($(QT_SYS_RES),)
	$(MAKE) -C $(PLUGIN_PARENT_DIR)$(QTUI_NAME) CXX=$(CXX) PLUGIN_LDFLAGS="$(PLUGIN_LDFLAGS)" PLUGIN_CXXFLAGS="$(PLUGIN_CXXFLAGS)" PLUGIN_BUILD_DIR=$(PLUGIN_BUILD_DIR) PLUGIN_PARENT_DIR=$(PLUGIN_PARENT_DIR) qt_ui-plugin
	@echo 'A plugin can be found here - $(QTUI_CXX_TGT)'
else
	@echo 'Qt not found - skipping qt-ui plugin'
endif
else
	@echo 'Qt not found - skipping qt-ui plugin'
endif

