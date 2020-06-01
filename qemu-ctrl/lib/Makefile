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
# *  Adam Critchley <shoggoth@cromulence.com>
# *
# * This work is licensed under the terms of the GNU GPL, version 2 or later.
# * See the COPYING file in the top-level directory.
# * 
# * The creation of this code was funded by the US Government.
# */

all: qemuctrl

qemuctrl:
	gcc -g -c -fPIC racomms.c -I include $(shell pkg-config --cflags glib-2.0) -o racomms.o $(shell pkg-config --libs glib-2.0)
	ar rcs libqemuctrl.a racomms.o

clean:
	rm libqemuctrl.a
