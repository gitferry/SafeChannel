#!/usr/bin/env python
# coding=utf-8

"""Usage:
     sc.py server <port>
     sc.py client <host> <port> <method>
     sc.py (-h | --help | --version)
"""
import socket
import threading
from docopt import docopt

def handle_client(client_socket):
        while True:
            try:
                received_content = client_socket.recv(1024)

                if received_content:
                    print "[*] Received: %s" % received_content

                client_socket.send("ACK!")
            except:
                client_socket.close()
                print "[*] Remote client is closed."
                return

def create_server(args):
    bind_ip = "0.0.0.0"
    bind_port = int(args['<port>'])

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((bind_ip, bind_port))

    server_socket.listen(5)

    print "[*] Server created. Listening on port:", args['<port>']

    while True:
        try:
            client_socket, address = server_socket.accept()

            print "[*] Accept connection from %s: %s" % (address[0], address[1])
            
            try:
                client_handler = threading.Thread(target=handle_client,
                                                  args=(client_socket,))
                client_handler.start()
            except:
                client_socket.close()
                print "[*] Remote client is closed."

        except KeyboardInterrupt, IOError:
            server_socket.close()
            client_socket.close()
            print "\n[*] Server is closed."
            return

    
def create_client(args):
    print "Client created. The host is", args['<host>'], ":", args['<port>']
    print "The message will be encrypted with", args['<method>']

    target_ip = args['<host>']
    target_port = int(args['<port>'])

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket.connect((target_ip, target_port))

    while True:
        try:
            message = raw_input('> ')
            client_socket.send(message)
            response_content = client_socket.recv(1024)

            print response_content

        except:
            client_socket.close()
            print "\n[*] Connection is broke."
            return

if __name__ == "__main__":
    arguments = docopt(__doc__, version='0.1.1rc')
    if arguments['server']:
        create_server(arguments)
    elif arguments['client']:
        create_client(arguments)
    
