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
from rsa import rsa
from docopt import docopt
from sha1 import sha1

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

def handle_rsa(client_socket):
    print "[*] The connection is encrypted with RSA"
    # generate keys
    try:
        prime_length = client_socket.recv(1024)
    except:
        client_socket.close()
        print "[*] Remote client is closed."
        return

    prime_length = int(prime_length)
    rsaKeys = rsa.RSAKey()
    pub_key, priv_key = rsaKeys.gen_keys(prime_length)

    # send public key
    print "[*] Keys generated. Sending public key to the client..."
    pub_key_string = str(pub_key[0]) + "," + str(pub_key[1])
    try:
        client_socket.send(pub_key_string)
    except:
        client_socket.close()
        print "\n[*] Connection is broke."
        return
 
    print "[*] Public key sent. Waiting for messages..."

    while True:
        try:
            cipher_text = client_socket.recv(5096)

            if cipher_text:
                print "[*] Received:\n%s" % cipher_text
                print "[*] Plain text is: %s" % rsaKeys.decrypt(priv_key, cipher_text.split())

            client_socket.send("ACK!")
        except:
            client_socket.close()
            print "\n[*] Connection is broke."
            return

def handle_sha1(client_socket):
    print "[*] Wating for the message and digest..."
    while True:
        try:
            message = client_socket.recv(2048)
            print message
            plain_text = message.split("+")[0]
            digest_text = message.split("+")[1]

            if digest_text and plain_text:
                print "[*] Received message: %s" % plain_text
                print "[*] Received digest: [%s]" % digest_text
                sha1_degist = sha1.sha1(plain_text)

                print "[*] Real digest: [%s]" % sha1_degist
                if sha1_degist == digest_text:
                    print "[*] The message is from correct client."
                else:
                    print"[*] The message was tampered."
                
            client_socket.send("ACK!")
        except:
            client_socket.close()
            print "\n[*] Connection is broke."
            return


def handle_mix(client_socket):
    # waiting for public key of the client
    print "Wating for public key of the client"
    try:
        pub_key_string_client = client_socket.recv(2048)
        pub_key_array_client = pub_key_string_client.split(',')
        pub_key_client = (long(pub_key_array_client[0]), long(pub_key_array_client[1]))
    except:
        client_socket.close()
        print "\n[*] Connection is broke."
        return

    print "[*] Client public key accepted."
    print pub_key_client

    prime_length = 512
    rsaKeys = rsa.RSAKey()
    pub_key_server, priv_key_server = rsaKeys.gen_keys(prime_length)

    # send public key
    print "[*] Keys generated. Sending public key to the client..."
    pub_key_string_server = str(pub_key_server[0]) + "," + str(pub_key_server[1])
    print pub_key_string_server
    try:
        client_socket.send(pub_key_string_server)
    except:
        client_socket.close()
        print "\n[*] Connection is broke."
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
    elif received_content == "method:rsa":
        handle_rsa(client_socket)
    elif received_content == "method:sha1":
        handle_sha1(client_socket)
    elif received_content == "method:mix":
        handle_mix(client_socket) 
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

def rsa_method(client_socket):

    # Waiting for the public key
    print "[*] Wating for the public key..."
    method_message = "method:rsa"
    client_socket.send(method_message)
    client_socket.recv(1024)
    
    print "[*] Please enter the bit length of the prime."
    bit_length = raw_input("> ")
    try:
        client_socket.send(bit_length)
        pub_key_string = client_socket.recv(2048)
        pub_key_array = pub_key_string.split(',')
        pub_key = (long(pub_key_array[0]), long(pub_key_array[1]))
    except:
        client_socket.close()
        print "\n[*] Connection is broke."
        return

    print "[*] Public key accepted."
    print "[*] Please enter the message."

    # send encrypted message
    rsaKeys = rsa.RSAKey()
    while True:
        try:
            plain_text = raw_input('> ')
            cipher_text = rsaKeys.encrypt(pub_key, plain_text)
            print "[*] The cipher is [%s]" % cipher_text
            client_socket.send(cipher_text)
            response_content = client_socket.recv(1024)

            print response_content

        except:
            client_socket.close()
            print "\n[*] Connection is broke."
            return


def sha1_method(client_socket):
    # send method
    method_message = "method:sha1"
    client_socket.send(method_message)
    client_socket.recv(1024)
    
    # send messages
    print "[*] Please enter the message."
    while True:
        try:
            plain_text = raw_input('> ')
            digest_text = sha1.sha1(plain_text)
            print "[*] The digest is [%s]" % digest_text
            client_socket.send(plain_text + "+" + digest_text)
            response_content = client_socket.recv(1024)

            print response_content
        except:
            client_socket.close()
            print "\n[*] Connection is broke."
            return


def mix_method(client_socket):
    # send method
    method_message = "method:mix"
    client_socket.send(method_message)
    client_socket.recv(1024)

    prime_length = 512
    rsaKeys = rsa.RSAKey()
    pub_key_client, priv_key_client = rsaKeys.gen_keys(prime_length)

    # send public key
    print "[*] RSA Keys generated. Sending public key to the server..."
    pub_key_string_client = str(pub_key_client[0]) + "," + str(pub_key_client[1])
    print pub_key_string_client
    try:
        client_socket.send(pub_key_string_client)
    except:
        client_socket.close()
        print "\n[*] Connection is broke."
        return
 
    print "[*] Public key sent. Waiting for the server public key..."

    # waiting for public key of the client
    print "Wating for public key of the server"
    try:
        pub_key_string_server = client_socket.recv(2048)
        pub_key_array_server = pub_key_string_server.split(',')
        pub_key_server = (long(pub_key_array_server[0]), long(pub_key_array_server[1]))
    except:
        client_socket.close()
        print "\n[*] Connection is broke."
        return

    print "[*] Server public key accepted."
    print pub_key_server

    
def create_client(args):
    print "Client created. The host is", args['<host>'], ":", args['<port>']
    print "The message will be encrypted with", args['<method>']

    target_ip = args['<host>']
    target_port = int(args['<port>'])

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((target_ip, target_port))
    except:
        print "[*] Server is not ready, please try again."
        return

    if args['<method>'] == "des":
        des_method(client_socket)
    elif args['<method>'] == "rsa":
        rsa_method(client_socket)
    elif args['<method>'] == "sha1":
        sha1_method(client_socket)
    elif args['<method>'] == "mix":
        mix_method(client_socket)
    else:
        return


if __name__ == "__main__":
    arguments = docopt(__doc__, version='0.1.1rc')
    if arguments['server']:
        create_server(arguments)
    elif arguments['client']:
        create_client(arguments)
    
