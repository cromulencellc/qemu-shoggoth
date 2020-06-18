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

import sys
import binascii
from pyqemu import *

def on_plugin_load(*args):
    print("args[0]" + str(args[0]))
    print("args[1]" + str(args[1]))
    print("SYS PATH" + str(sys.path))

#def on_command(cmd, args):
#    print('on_command')

#def on_ra_start(work_item):
#    print("Python: RA Started")

#def on_ra_stop(work_results):
#    print("Python: RA Stopped")
#    print(work_results.buffer)

#def on_ra_idle():
#    print("Python: RA Idle")

#def get_ra_report_type():
#    return 1

#def on_breakpoint(cpu_id, pc, bp_id):
#    print("Python: Breakpoint hit")

#def on_exception(exception):
#    print('on_exception')

#def on_execute_instruction(vaddr, addr):
#    print("Python: On Instruction")

#def on_memory_write(paddr, pval, pbytes):
#    print("Python: On Memory Write " + hex(paddr) + " value " + hex(pval))
#    print(binascii.hexlify(CPU.getPhysicalMemory(paddr, len(pbytes))))

#def on_memory_read(paddr, vaddr, pval, pbytes):
#    print("Python: On Memory Read " + hex(paddr) + " value " + hex(pval))
#    print(binascii.hexlify(CPU.getPhysicalMemory(paddr, len(pbytes))))

#def on_syscall(number, args):
#    print("on_syscall")

#def on_syscall_exit(number, args):
#    print("on_syscall_exit")

#def on_vm_change_state(running, state):
#    print('on_vm_change_state' , running)

#def on_interrupt(interrupt):
#    print('on_interrupt')

#def on_packet_recv(data):
#    print('on_packet_recv: ', ''.join('{:02x}'.format(x) for x in bytearray(data)))
#    return None

#def on_packet_send(data):
#    print('on_packet_send ', ''.join('{:02x}'.format(x) for x in bytearray(data)))
#    return None

#def on_vm_startup():
#    print('on_vm_startup')

#def on_vm_shutdown():
#    print('on_vm_shutdown')
