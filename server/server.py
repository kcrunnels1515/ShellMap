# import all functions from http.server module

from enum import Enum
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import *
from urllib.parse import urlparse
import datetime

def encode(data: str) -> str:
    # key for XOR encoding is current minute
    key = int(datetime.datetime.now().minute)
    # characters encoded into hex strings
    data_as_hex = data.encode().hex()
    # convert characters into integers
    hex_lst = [int(data_as_hex[i:i+2], 16) for i in range(0, len(data_as_hex), 2)]

    # xor encode data
    encoded_lst = [format(key ^ a, '#04x')[2:] for a in hex_lst]

    # place key at beginning of encoded data list
    encoded_lst.insert(0, format(key, '#04x')[2:])

    return ''.join(encoded_lst)

def decode(data: str) -> str:
    # convert string of hex values to list of integers
    hex_data = [int(data[i:i+2], 16) for i in range(0, len(data), 2)]
    # isolate key and data
    key = hex_data[0]
    args = hex_data[1:]

    # decode data by XORing key with all args
    decoded = [format(key ^ arg, '#04x')[2:] for arg in args]

    # convert hex string to ascii string
    return bytearray.fromhex(''.join(decoded)).decode()

'''
Specification of arguments to nmap

host_disc ::= '-'s[LnSTAU]

options ::= '-'(p' '?port_list | sV)

port_list ::= port_elem | port_elem (',' | ' '+',') port_list
port_elem ::= port | port '-' port
port ::= [1-65535]

'''

class Argument:
    def __init__(self, arg_str):
        self.arg_strs = arg_str.split(' ')
        self.ind = 0
        self.flags = []
        self.ports = []
        self.addrs = dict()

#    def parse_args(self):


    def add_flag(self, flag):
        self.flags.add(flag)



class Flag(Enum):
    PING_SCAN = 1
    ICMP_SCAN = 2
    PORT_SCAN = 3
    LIST_SCAN = 4
    NO_HOST_DISC = 5
    PORT_RANGE = 6
    IPV6 = 7
    TRACERT = 8
    ALL = 9

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = urlparse(self.path).query
        query_components = dict(qc.split("=") for qc in query.split("&"))
        args = query_components['args']

        if len(args) > 0:
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write()


#if __name__ == "__main__":
#    print(decode(encode("this is a test string")))
