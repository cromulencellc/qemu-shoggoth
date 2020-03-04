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
from time import time
from plugin import *

run_data = [bytearray(), bytearray()]
run_index = 0
run_number = 0
ins_num = 1

def on_plugin_load():
    print "SYS PATH" + str(sys.path)


def on_ra_start(work_item):
    global run_data
    global run_number
    global start_time
    run_data[1] = bytearray()
    run_number += 1
    print 'Started round ', run_number, ' of RA'
    start_time = time()


def on_ra_stop(work_results):
    global run_data  
    global run_number
    global run_index
    global ins_num
    global start_time

    end_time = time()
    elapsed = end_time - start_time
    print 'Finished round ', run_number, ' of RA: ', ins_num, ' instructions (', elapsed , ' Seconds)'
    if run_index == 0:
        run_index += 1  
    ins_num = 1
    if run_number > 1:
        test_a = run_data[0]
        test_b = run_data[1]
        if test_a != test_b:
            print 'Run ', run_number, ' differed from other runs'
            quit_vm()
        print 'Runs  1 and ', run_number ,' are equivalent'     


def execute_instruction(vaddr, addr):
    global run_data
    global run_index
    global ins_num
    ins_num += 1
    regs = get_register_names()
    cpu = get_current_cpu()

    for r in regs:
        run_data[run_index].extend(get_cpu_register(cpu, r)[0])
    run_data[run_index].extend(addr)

