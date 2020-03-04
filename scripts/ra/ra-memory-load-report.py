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
import os
from time import time
from datetime import datetime
from plugin import *


run_data = [dict(), dict()]
run_number = 0
ins_num = 0
write_file = 0

def on_plugin_load():
    global write_file
    if not os.path.exists('tests'):
        os.makedirs('tests')

    now = datetime.now()
    dt_string = now.strftime("%Y%m%d%H%M%S")
    file_name = 'tests/memory-report-%s.txt' % dt_string
    write_file = open(file_name,"w+")


def on_ra_start(work_item):
    global run_data
    global run_number

    if run_number > 0:

        rep = '====================================================================\n'
        rep += 'Load Report: %d\n\n' % run_number
        run_data[1] = dict()

        if run_number > 1:
            for addr in range(0, 268435456, 4096):
                run_data[1][addr] = get_physical_memory(addr, 4096)

            for old_address in sorted(run_data[0].keys()):
                if old_address in run_data[1]:
                    if run_data[0][old_address] != run_data[1][old_address]:
                        rep += 'Page at %.8x was different than last load %d\n' % (old_address, run_number)
                else:
                    rep += '%.8x is not available in iteration %d\n' % (old_address, run_number)
            
        else:
            for addr in range(0, 268435456, 4096):
                run_data[0][addr] = get_physical_memory(addr, 4096)

        rep += '====================================================================\n'
        rep += '\n'
        print rep


def on_ra_stop(work_results):
    global run_data
    global run_number

    if run_number > 0: 
        rep = '====================================================================\n'
        rep += 'Run Report: %d\n\n' % run_number    

        index = 0
        if run_number > 1:
            index = 1

        mem_state = dict()
        
        for addr in range(0, 268435456, 4096):
            mem_state[addr] = get_physical_memory(addr, 4096)

        for eff_addr in sorted(run_data[index].keys()):
            if eff_addr in mem_state:
                if run_data[index][eff_addr] != mem_state[eff_addr]:
                    rep += 'Page at %.8x was effected in run %d\n' % (eff_addr, run_number)
            else:
                rep += 'Page at %.8x was not found in run number %d\n' % (eff_addr, run_number)

        rep += '====================================================================\n'
        rep += '\n'
        print rep                

    run_number += 1


def on_vm_shutdown():
    global write_file
    print 'VM shutdown detected: closing memory report file.'





   

