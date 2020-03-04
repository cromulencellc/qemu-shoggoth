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

from random import *
from ctypes import *
from struct import *
from Messaging import *
from Messages import *
from Connection import *


# We'll make a class that eumuales QEMU
class QEMUSimulator(MessageActionCenter):

    def __init__(self, client):

        # Initialize the action center
        super(QEMUSimulator, self).__init__()

        # Add message processors
        self.add_action(MessageType.MSG_REQUEST_JOB_ADD, self._processCommsResponseJobAddMsg)
        self.add_action(MessageType.MSG_REQUEST_RST, self._processCommsRequestRapidSaveTreeMsg)

        # Make the connection to the  server
        self._server_connection = client.connect()
        
        # Run the simulator
        self._simulate()


    def _simulate(self):

        print 'Starting QEMU Simulator.'
        print 'Any messages sent to this simulator will'
        print 'be responded to.'
        print ''
        
        # Begin the simulator loop
        while True:

            # We may error out if there is nothing 
            # to read off the socket
            try:
                # Read a request
                request = self._server_connection.read_message()
            
                # Process the request.
                self.process_message(request)
            except BufferError: 
                # This may not be a big deal
                pass
            except KeyboardInterrupt:
                # Keyboard interrupt to stop
                print ''
                print 'Now exiting simulation loop.'
                break


    def _processCommsResponseJobAddMsg(self, message):

        # Print the message that we read
        print 'Processing Message:'
        print message
        print ''

        # Copy the Job ID and Queue
        job_id = message.get_job_id()
        queue_num = message.get_queue_num()

        # Generate a random hash
        hash = []
        for x in range(5):
            val = c_uint32(randint(0x00, 0xffffffff))
            hash.append(val.value)

        # Generate a response 
        response = CommsResponseJobReportMsg(queue_num, job_id, hash)

        # Add report info
        proc = CommsResponseJobReportProcessorEntry(0x2, 'Froopy')
        response.add_param(proc)

        # Add some registers
        r1 = CommsResponseJobReportRegisterEntry(0x00, 1, 'r1', pack('B', randint(0x00, 0xff)))
        r2 = CommsResponseJobReportRegisterEntry(0x01, 1, 'r2', pack('B', randint(0x00, 0xff)))
        r3 = CommsResponseJobReportRegisterEntry(0x02, 1, 'r3', pack('B', randint(0x00, 0xff)))
        r4 = CommsResponseJobReportRegisterEntry(0x02, 1, 'r4', pack('B', randint(0x00, 0xff)))
        response.add_param(r1)
        response.add_param(r2)
        response.add_param(r3)
        response.add_param(r4)

        # Add some memory regions
        m1 = CommsResponseJobReportMemoryEntry(0xcfa0, 8, pack('Q', randint(0x00, 0xffffffffffffffff)))
        m2 = CommsResponseJobReportMemoryEntry(0xffa0, 8, pack('Q', randint(0x00, 0xffffffffffffffff)))
        response.add_param(m1)
        response.add_param(m2)

        # Print the response
        print 'Sending Response:'
        print response
        print ''

        # Send the message
        self._server_connection.send(response)


    def _processCommsRequestRapidSaveTreeMsg(self, message):

        # Print the message that we read
        print 'Processing Message:'
        print message
        print ''        

        # Copy the Job ID and Queue
        job_id = message.get_job_id()
        queue_num = message.get_queue_num()

        # Create a response
        response = CommsResponseRapidSaveTreeMsg(queue_num, job_id)

        # Print the response
        print 'Sending Response:'
        print response
        print ''

        # Send the message
        self._server_connection.send(response)


# Check args
if len(sys.argv) >= 2:

    # We should have passed in a listen port as an argument
    port = int(sys.argv[1])    

    # We want to set up a message processor
    messageing = MessagingCenter()

    # create a connection to the server
    client = Client('localhost', port, messageing)

    # Run the simulator
    QEMUSimulator(client)
 
else:
    # There was not a port argument passed in
    raise RuntimeError('A port must be provided as an argument to use this script.')