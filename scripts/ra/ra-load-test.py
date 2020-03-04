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

import sys
import binascii
from plugin import *

run_data = [bytearray(), bytearray()]
run_index = 0
run_number = 0

def on_plugin_load():
    print 'Begenning Image Load Load Test'
    print '    Note: If you are setting registers in your job set up, this will fail'

def on_ra_start(work_item):
    global run_data
    global run_index
    global run_number

    regs = get_register_names()
    cpu = get_current_cpu()
  
    run_data[1] = bytearray()

    if run_number > 0:
        print 'Running test ', run_number        
        for r in regs:
            run_data[1].extend(get_cpu_register(cpu, r)[0])
        if run_data[0] != run_data[1]:
            print 'There was an error on interation ', run_number
            quit_vm()
    else:
        for r in regs:
            run_data[0].extend(get_cpu_register(cpu, r)[0])

    run_number += 1


