# import all functions from http.server module

from enum import Enum
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import *
from urllib.parse import urlparse
import datetime
import custom_optparse as co
from optparse import OptionParser
import os

# load module file name
modular_files = [ f.path for f in os.scandir(os.path.join(os.getcwd(), "modules")) if f.is_file() ]

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

class Argument:
    def __init__(self):
        self.flags = []
        self.ports = []
        self.addrs = dict()
        self.regexes = dict()
        self.parser = OptionParser(option_class=ShellMapOption)
        self.load_parser_rules()

    def load_parser_rules(self):
        self.parser.add_option("-p", action="store", type="port_list", dest="ports")
        self.parser.add_option("-sL", action="store_true", dest="list_scan", default=False)
        self.parser.add_option("-sn", action="store_true", dest="ping_scan", default=False)
        self.parser.add_option("-Pn", action="store_false", dest="host_disc", default=True)
        self.parser.add_option("-PS", action="store", type="port_list", dest="port_syn")
        self.parser.add_option("-PA", action="store", type="port_list", dest="port_ack")
        self.parser.add_option("-PU", action="store", type="port_list", dest="port_udp")
        self.parser.add_option("-PY", action="store", type="port_list", dest="port_sctp")
        self.parser.add_option("-PE", action="store_true", dest="icmp_echo", default=False)
        self.parser.add_option("-PP", action="store_true", dest="icmp_timestamp", default=False)
        self.parser.add_option("-PM", action="store_true", dest="icmp_netmasq", default=False)
        self.parser.add_option("-n", action="store_false", dest="no_resolv", default=True)
        self.parser.add_option("-sS", action="store_const", const="SYN", dest="port_default_scan", default="SYN")
        self.parser.add_option("-sT", action="store_const", const="CON", dest="port_default_scan", default="SYN")
        self.parser.add_option("-sA", action="store_const", const="ACK", dest="port_default_scan", default="SYN")
        self.parser.add_option("-sU", action="store_true", dest="port_udp_default", default=False)
        self.parser.add_option("--exclude-ports", action="store", type="port_list", dest="excluded_ports")
        self.parser.add_option("-F", action="store_true", dest="limit_ports", default=False)
        self.parser.add_option("-r", action="store_false", dest="randomize_ports", default=True)
        self.parser.add_option("--top-ports", action="store", type="int", dest="top_ports")
        self.parser.add_option("-sV", action="store_true", dest="service_version", default=False)
        self.parser.add_option("-O", action="store_true", dest="os_detect", default=False)

    def parse(self, arg_str):
        return self.parser.parse_args(arg_str.split(' '))


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
    def __init___(self):
        self.cur_arg = Argument()

    def collect_script(self, arg_str):
        return "test"

    def do_GET(self):
        query = urlparse(self.path).query
        query_components = dict(qc.split("=") for qc in query.split("&"))
        if len(query_components) <= 0 or "args" not in query_components:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write("no args\n")
        else:
            query_str = decode(query_components['args'])
            if len(query_str) > 0:
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(encode(collect_script(query_str)))
            else:
                self.send_response(404)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write("no args\n")


def run_server(server_class=HTTPServer, handler_class=RequestHandler, port=8000):
    server_addr = ('', port)
    httpd = server_class(server_addr, handler_class)
    httpd.serve_forever()


if __name__ == "__main__":
    run_server()
