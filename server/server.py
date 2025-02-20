# import all functions from http.server module
import ast
from enum import Enum
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import *
from urllib.parse import urlparse
import datetime
import custom_optparse as co
from optparse import OptionParser
import os
from pathlib import Path

# load module names and file paths as tuples
module_files = [ (Path(f.path).stem, f.path) for f in os.scandir(os.path.join(os.getcwd(), "modules")) if f.is_file() ]

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
        self.dependencies = dict()
        # declare parser with custom argument parsing options
        self.parser = OptionParser(option_class=ShellMapOption)
        self.load_parser_rules()
        # takes a list of tuples (module_name, module_file_path)
        self.modules = [ (Path(f.path).stem, f.path) for f in os.scandir(os.path.join(os.getcwd(), "modules")) if f.is_file() ]
        self.load_dependencies()

    def load_parser_rules(self):
        # options that add data
        self.parser.add_option("-p", action="store", type="port_list", dest="ports")
        self.parser.add_option("-PS", action="store", type="port_list", dest="ports_syn")
        self.parser.add_option("-PA", action="store", type="port_list", dest="ports_ack")
        self.parser.add_option("-PU", action="store", type="port_list", dest="ports_udp")
        self.parser.add_option("-PY", action="store", type="port_list", dest="ports_sctp")
        self.parser.add_option("--exclude-ports", action="store", type="port_list", dest="excluded_ports")
        self.parser.add_option("--top-ports", action="store", type="int", dest="top_ports")

        # options that modify behavior
        self.parser.add_option("-sL", action="store_true", dest="list_scan", default=False)
        self.parser.add_option("-sn", action="store_true", dest="ping_scan", default=False)
        self.parser.add_option("-Pn", action="store_false", dest="host_disc", default=True)
        self.parser.add_option("-PE", action="store_true", dest="icmp_echo", default=False)
        self.parser.add_option("-PP", action="store_true", dest="icmp_timestamp", default=False)
        self.parser.add_option("-PM", action="store_true", dest="icmp_netmasq", default=False)
        self.parser.add_option("-n", action="store_false", dest="no_resolv", default=True)
        self.parser.add_option("-sU", action="store_true", dest="port_udp_default", default=False)
        self.parser.add_option("-F", action="store_true", dest="limit_ports", default=False)
        self.parser.add_option("-r", action="store_false", dest="randomize_ports", default=True)
        self.parser.add_option("-sV", action="store_true", dest="service_version", default=False)
        self.parser.add_option("-O", action="store_true", dest="os_detect", default=False)
        self.parser.add_option("-sS", action="store_const", const="SYN", dest="port_default_scan", default="SYN")
        self.parser.add_option("-sT", action="store_const", const="CON", dest="port_default_scan", default="SYN")
        self.parser.add_option("-sA", action="store_const", const="ACK", dest="port_default_scan", default="SYN")


    # we will not support ranged ips: 192.168.0-255.1-255
    # domain names must not have slashes: slashes are only used to designate subnets
    def check_host_list(self, host_list):
        val_lst = [ h.replace(" ", "").split(',') for h in host_list]
        ret_lst = []
        for p in val_lst:
            if '/' in p:
                p_lst = p.split("/")
                # if the element has a subnet, convert it to an int
                ret_lst.append(p_lst[0], int(p_lst[1]))
            else:
                ret_lst.append((int(p), 0))
        return ret_lst

    def load_dependencies(self):
        with open('module_deps.txt', 'r') as deps:
            # reads a dependency file line by line
            # each line is of the format:
            #   A B C
            # where A is a module, and B and C are modules that A
            # depends on
            for line in deps:
                line_fields = line.strip().split(' ')

                if len(line_fields == 1):
                    # no dependency
                    self.dependencies[line_fields[0]] = []
                else:
                    # has dependency
                    self.dependencies[line_fields[0]] = line_fields[1:]
    def process_args(self, arg_str):
        # collect options and arguments from parsing the input
        # args should just be a list of hosts
        (options, args) = self.parser.parse_args(arg_str.split(' '))
        # interpret list of hosts as list of (host, subnet) pairs
        hosts = check_host_list(args)
        opt_dict = ast.literal_eval(str(options))

        # collect required functional modules
        fm_lst = collect_modules(opt_dict)


    def collect_modules(self, options):
        deps_col = []
        deps = []

        for k in options.keys():
            deps_col.extend(fd_helper(k))

        for i in deps_col:
            if i in deps:
                pass
            else:
                deps.append(i)

        return deps

    def fd_helper(self, k):
        if (len(self.dependencies[k]) == 0):
            return list(k)
        else:
            sub_deps = []
            for dep in self.dependencies[k]:
                sub_deps.extend(fd_helper(dep))
            sub_deps.append(k)
            return sub_deps


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
