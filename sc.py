#!/usr/bin/env python
# coding=utf-8

"""Usage:
     sc.py server <port>
     sc.py client <host> <port> <method>
     sc.py (-h | --help | --version)
"""
from docopt import docopt

def create_server(args):
    print "Server created. Listening on port:", args['<port>']

def create_client(args):
    print "Client created. The host is", args['<host>'], ":", args['<port>']
    print "The message will be encrypted with", args['<method>']

if __name__ == "__main__":
    arguments = docopt(__doc__, version='0.1.1rc')
    if arguments['server']:
        create_server(arguments)
    elif arguments['client']:
        create_client(arguments)
    
