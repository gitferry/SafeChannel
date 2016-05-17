#!/usr/bin/env python
# coding=utf-8

"""Usage:
     sc.py server <port>
     sc.py client <host> <port> <method>
     sc.py (-h | --help | --version)
"""
import socket
import threading
from des import DES
from docopt import docopt

def handle_des(client_socket):
    print "[*] The connection is encrypted with DES"
    # waiting for key
    print "[*] Waiting for key..."
    try:
        key_text = client_socket.recv(1024)
        client_socket.send("Key received!")
    except:
        client_socket.close()
        print "[*] Remote client is closed."
        return

    print "[*] Key accepted. Waiting for messages..."

    while True:
        try:
            cipher_text = client_socket.recv(1024)

            if cipher_text:
                print "[*] Received: %s" % cipher_text
                print "[*] Plain text is: %s" % DES.decrypt(cipher_text, key_text)

            client_socket.send("ACK!")
        except:
            client_socket.close()
            print "[*] Remote client is closed."
            return

def handle_client(client_socket):
    # waiting for method
    try:
        received_content = client_socket.recv(1024)
        client_socket.send("ACK")
    except:
        client_socket.close()
        print "[*] Remote client is closed."
        return 
    if received_content == "method:des":
        handle_des(client_socket)
    else:
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


def des_method(client_socket):

    # send methond message
    method_message = "method:des"
    try:
        client_socket.send(method_message)
        client_socket.recv(1024)
    except:
        client_socket.close()
        print "\n[*] Connection is broke."
        return

    # send des key
    print "[*] Please enter the key, and the length must longer than 8 characters."
    while True:
        key_text = raw_input("> ")
        if len(key_text) > 8:
            break
        else:
            print "[!] The length must longer than 8 characters.\
                    Please try again:)."
    try:
        client_socket.send(key_text)
        client_socket.recv(1024)
    except:
        client_socket.close()
        print "\n[*] Connection is broke."
        return

    print "[*] Please enter the message:"
    
    # send encrypted message
    while True:
        try:
            plain_text = raw_input('> ')
            cipher_text = DES.encrypt(plain_text, key_text)
            print "[*] The cipher is [%s]" % cipher_text
            client_socket.send(cipher_text)
            response_content = client_socket.recv(1024)

            print response_content

        except:
            client_socket.close()
            print "\n[*] Connection is broke."
            return

    
def create_client(args):
    print "Client created. The host is", args['<host>'], ":", args['<port>']
    print "The message will be encrypted with", args['<method>']

    target_ip = args['<host>']
    target_port = int(args['<port>'])

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((target_ip, target_port))

    if args['<method>'] == "des":
        des_method(client_socket)
    else:
        return


if __name__ == "__main__":
    arguments = docopt(__doc__, version='0.1.1rc')
    if arguments['server']:
        create_server(arguments)
    elif arguments['client']:
        create_client(arguments)
    
