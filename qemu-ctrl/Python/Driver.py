#!/usr/bin/python3
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

from pyqemu.connection import JobServer
from pyqemu.messages import *

if __name__ == "__main__":
    # Check args
    if len(sys.argv) >= 3:

        # We should have passed in a listen port as an argument
        # as well as a byte string for the hash
        port = int(sys.argv[1])
        base_hash = str(sys.argv[2])

        # Establish a connection with a client
        server = JobServer("0.0.0.0", port)
        client_connection = server.wait_for_connection()

        # Now we can send a message
        message = CommsMessage() / CommsRequestJobAddMsg(
                    queue = 1,
                    job_id = 100,
                    base_hash = base_hash,
                    entries = [
                        CommsRequestJobAddTimeoutSetup(timeout=60000)
                    ])
        print('Sending message:')
        message.show()
        client_connection.send(message)

        # Wait for a reply
        reply = client_connection.read_message()
        print('Received message:')
        reply.show()

        # Now we will ask for an RST
        message = CommsMessage() / CommsRequestRapidSaveTreeMsg(
                    queue = 1,
                    job_id = 100
                    )
        print('Sending message')
        message.show()
        client_connection.send(message)

        # Now we will get a reply
        reply = client_connection.read_message()
        print('Received message:')
        reply.show()

        # Close sockets
        client_connection.close()
        server.close()

    else:
        # There was not a port argument passed in
        raise RuntimeError('A port and hash must be provided as arguments to use this script.')
