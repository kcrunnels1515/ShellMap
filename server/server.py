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
        # creates a mapping between functional modules and their corresponding files
        self.modules = dict([ (Path(f.path).stem, f.path) for f in os.scandir(os.path.join(os.getcwd(), "modules")) if f.is_file() ])
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

        # options that store a string as their value are maps to a functional module
        # ex: these tell the fd determiner that it should add a particular module
        self.parser.add_option("-sS", action="store_const", const="port_syn_scan", dest="port_default_scan", default="port_syn_scan")
        self.parser.add_option("-sT", action="store_const", const="port_con_scan", dest="port_default_scan", default="port_syn_scan")
        self.parser.add_option("-sA", action="store_const", const="port_ack_scan", dest="port_default_scan", default="port_syn_scan")

    def record_port_scan(option, opt_str, value, parser):
        if (opt_str == "-sS"):
            parser.values.port_syn_scan = True
        elif (opt_str == "-sT"):
            parser.values.port_con_scan = True
        elif (opt_str == "-sA"):
            parser.values.port_con_scan = True

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
        # string to hold all of the required script text
        script_str = ""
        # collect options and arguments from parsing the input
        # args should just be a list of hosts
        (options, args) = self.parser.parse_args(arg_str.split(' '))
        # interpret list of hosts as list of (host, subnet) pairs
        hosts = check_host_list(args)
        opt_dict = ast.literal_eval(str(options))

        # collect required functional modules, and arguments to those functional modules
        fm_lst, opt_args = collect_modules(opt_dict)

        # add option arguments and target specs to beginning as global variables
        for k, v in opt_args.items():
            tmp_str = "$" + k.upper() + " = " + v

        # use mapping between fd names and modules to concatenate scripts


    def collect_modules(self, options):
        deps = []
        added = dict.fromkeys(self.dependencies.keys(), False)
        opt_args = {}

        for k in options.keys():
            fd_helper(k, deps, added, opts)
            if not isinstance(options[k], str) and not isinstance(options[k], bool):
                opt_args[k] = options[k]

        return (deps, opt_args)

    def fd_helper(self, k, dep_lst, added_dict, opts):
        # if option holds a string, set the key to that string
        if isinstance(opts[k], str):
            k = opts[k]

        if not added_dict[k]:
            return

        # if a functional module has no dependencies, check that
        # it isn't already added and is it isn't, add it
        if (len(self.dependencies[k]) == 0):
            dep_lst.append(k)
            added_dict[k] = True
        # otherwise if the module has dependencies, recursively add
        # the dependencies and then add the initial module
        else:
            for dep in self.dependencies[k]:
                fd_helper(dep, dep_lst, added_dict)
            deps_lst.append(k)
            added_dict[k] = True


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
