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

import socket

from pyqemu.messages import *

class ConnectionManager(object):
    COMMS_MESSAGE_SIZE = CommsMessage.sizeof_comms_message()

    """ Manages a connection with a client.

       This class defines an interface that is used
       to communicate with a client. Messages from the 
       client will be decoded and returned as an object.

        Parameters
        ----------
        socket : socket
           The socket that will be used to communicate with the client.
    """

    def __init__(self, socket):

        self._client = socket


    def send(self, message):
        """ Sends a message to the client.

            This method sends the given message to the
            client.

           Parameters
           ----------
           message : CommsMessage
              The message that will be sent to the client.            
        """

        self._client.sendall(str(message))


    def read_message(self):
        """ Reads a message from the client.

            This method reads the client connection for data. When
            data arrives, it is processed and decoded. 

            Returns
            -------
            CommsMessage
                A decoded message from the client.             
        """

        # Make a temporary header
        hdr_bytes = self.read_data(ConnectionManager.COMMS_MESSAGE_SIZE)
        msg_hdr = CommsMessage(hdr_bytes)
        msg_size = long(msg_hdr.size) - ConnectionManager.COMMS_MESSAGE_SIZE

        # Now read the entire message
        if msg_size > 0:
            msg_bytes = self.read_data(msg_size)
            return CommsMessage(hdr_bytes + msg_bytes)

        return None

    def read_data(self, amount):
        """ Reads an amount of data from the client.
        
            This method reads an amount from the client socket.

            Returns
            -------
            str
                Data read from the client socket.              
        """

        ret_val = self._client.recv(amount, socket.MSG_WAITALL)

        if len(ret_val) < amount:
            raise BufferError('Could not read the desired amount from the connection.')

        return ret_val 


    def close(self):
        """ Closes the client connection.

            This method closes the client connection.
        """

        self._client.close()



class JobServer(object):
    """ Creates a server to wait for client connections.

        This class defines a server socket on the provided
        port. It will await a connection then spawn off a client 
        connection when the connection arrives. The client connection
        will be able to send messages and decode incoming messages. 

        Note
        ----
        A JobServer object can be reused when a connection ends.

        Parameters
        ----------
        host : str
            This is the address of the interface that the server will listen on.
        port : int
           The port that the server will listen on.       
        message_center : MessagingCenter
            The object that will decode incoming messages.         
    """

    def __init__(self, host, port):

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self._socket.bind((host, port))
        self._socket.listen(socket.SOMAXCONN)

    def wait_for_connection(self):
        """ Waits for a connection.

            Waits for a connection and builds a client connection
            that will allow communication with the new client.

            Returns
            -------
            ConnectionManager
                An object that provides an interface to communicate with the connection.              
        """

        return ConnectionManager(self._socket.accept()[0]) 

    def close(self):
        """ Closes the server socket.

            This method closes this server socket.
        """
        self._socket.close()



class JobClient(object):
    """ Creates a client connection to a server. 

        This class creates a connection to a server
        and returns an interface that can be used to 
        communicate with that server.

        Note
        ----
        A client connection is closed when the connection manager is closed.

        Parameters
        ----------
        host : str
            This is the address of the server that the client will connect to.
        port : int
            This is the port on the server that the client will connect through.
    """

    def __init__(self, host, port, message_center):

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._host_ip = host
        self._host_port = port


    def connect(self):
        """ Initiates a connection with the specified server.

            This method initiates a connection with the specified server.
            It returns a connection manager that is loaded with a connection
            to the client once the connection is established.

            Returns
            -------
            ConnectionManager
                An object that provides an interface to communicate with the connection.            
        """

        self._socket.connect((self._host_ip, self._host_port))
        return ConnectionManager(self._socket)

