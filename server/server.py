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
import re

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
        # map between modules and list of modules they depend on
        self.dependencies = dict()
        # map between modules and the variables they need to have set
        self.variables = dict()
        # declare parser with custom argument parsing options
        self.parser = OptionParser(option_class=co.ShellMapOption)
        self.load_parser_rules()
        # creates a mapping between functional modules and their corresponding files
        self.modules = dict([ (Path(f.path).stem, f.path) for f in os.scandir(os.path.join(os.getcwd(), "modules")) if f.is_file() ])
        self.load_dependencies()

    def load_parser_rules(self):
        # options that add data
        self.parser.add_option("-p", action="store", type="port_list", dest="ports")
        self.parser.add_option("--PS", action="store", type="port_list", dest="ports_syn")
        self.parser.add_option("--PA", action="store", type="port_list", dest="ports_ack")
        self.parser.add_option("--PU", action="store", type="port_list", dest="ports_udp")
        self.parser.add_option("--PY", action="store", type="port_list", dest="ports_sctp")
        self.parser.add_option("--exclude-ports", action="store", type="port_list", dest="excluded_ports")
        self.parser.add_option("--top-ports", action="store", type="int", dest="top_ports")

        # options that modify behavior
        self.parser.add_option("--sL", action="store_true", dest="list_scan", default=False)
        self.parser.add_option("--sn", action="store_true", dest="ping_scan", default=False)
        self.parser.add_option("--Pn", action="store_false", dest="host_disc", default=True)
        self.parser.add_option("--PE", action="store_true", dest="icmp_echo", default=False)
        self.parser.add_option("--PP", action="store_true", dest="icmp_timestamp", default=False)
        self.parser.add_option("--PM", action="store_true", dest="icmp_netmasq", default=False)
        self.parser.add_option("-n", action="store_false", dest="resolve", default=True)
        self.parser.add_option("--sU", action="store_true", dest="port_udp_default", default=False)
        self.parser.add_option("-F", action="store_true", dest="limit_ports", default=False)
        self.parser.add_option("-r", action="store_false", dest="randomize_ports", default=True)
        self.parser.add_option("--sV", action="store_true", dest="service_version", default=False)
        self.parser.add_option("-O", action="store_true", dest="os_detect", default=False)

        # options that store a string as their value are maps to a functional module
        # ex: these tell the fd determiner that it should add a particular module
        self.parser.add_option("--sS", action="store_const", const="port_syn_scan", dest="port_default_scan", default="port_syn_scan")
        self.parser.add_option("--sT", action="store_const", const="port_con_scan", dest="port_default_scan", default="port_syn_scan")
        self.parser.add_option("--sA", action="store_const", const="port_ack_scan", dest="port_default_scan", default="port_syn_scan")

    def load_dependencies(self):
        #breakpoint()
        with open('module_deps.txt', 'r') as deps:
            # reads a dependency file line by line
            # each line is of the format:
            #   A B C [| VARIABLE]
            # where A is a module, and B and C are modules that A
            # depends on, and the optional VARIABLE is a global variable that
            # A will set
            # for example, setting a port list will require functionality AND data accessible
            mods = []
            var = ""
            for line in deps:
                if '|' in line:
                    mods_n_var = line.split('|')
                    mods = re.findall(r"[a-zA-Z0-9-_]+", mods_n_var[0])
                    var = mods_n_var[1].strip()
                else:
                    mods = re.findall(r"[a-zA-Z0-9-_]+", line)

                if len(mods) == 1:
                    # no dependency
                    self.dependencies[mods[0]] = []
                else:
                    # has dependency
                    self.dependencies[mods[0]] = mods[1:]

                if len(var) > 0:
                    self.variables[mods[0]] = var

    def process_args(self, arg_str):
        # string to hold all of the required script text
        script_str = ""
        # collect options and arguments from parsing the input
        # args should just be a list of hosts
        (options, args) = self.parser.parse_args(arg_str.split(' '))
        # interpret list of hosts as list of (host, subnet) pairs
        hosts = self.convert_targets(args)
        opt_dict = ast.literal_eval(str(options))

        # collect required functional modules, and arguments to those functional modules
        fm_lst, opt_args = self.collect_modules(opt_dict)
        #breakpoint()
        # add option arguments and target specs to beginning as global variables
        for k, v in opt_args.items():
            script_str += f"${k.upper()} = {v}\n"

        # use mapping between fd names and modules to concatenate scripts
        for mod in fm_lst:
            with open(self.modules[mod], 'r') as mod_file:
                script_str += mod_file.read() + "\n"

        return script_str

    def collect_modules(self, options):
        deps = []
        added = dict.fromkeys(self.dependencies.keys(), False)
        opt_args = {}
        #breakpoint()
        for k in options.keys():
            if options[k] is not None:
                self.fd_helper(k, deps, added, options)
                if isinstance(options[k], list):
                    opt_args[self.variables[k]] = self.convert_portlist(options[k])
                elif isinstance(options[k], int):
                    opt_args[self.variables[k]] = str(options[k])

        return (deps, opt_args)

    def fd_helper(self, k, dep_lst, added_dict, opts):
        #breakpoint()
        if opts[k] is None:
            return
        if opts[k] == False:
            return
        # if option holds a string, set the key to that string
        if isinstance(opts[k], str):
            k = opts[k]

        if added_dict[k]:
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
                self.fd_helper(dep, dep_lst, added_dict)
            deps_lst.append(k)
            added_dict[k] = True

    def convert_portlist(self, port_lst):
        ret_str = "@("
        for port, rng in port_lst:
            ret_str += "[PSCustomObject]@{ PORT = " + str(port) +"; RANGE = " + str(rng) + "},"
        ret_str = ret_str[:-1] + ")"
        return ret_str

    def convert_targets(self, host_lst):
        # just a list of targets, as specified in CLI
        # have to join and then split, bc args are split on spaces
        #
        # we will not support ranged ips: 192.168.0-255.1-255
        # domain names must not have slashes: slashes are only used to designate subnets
        val_lst = "".join(host_lst).split(',')
        ret_str = "@("
        for host in val_lst:
            if '/' in host:
                # get subnet size
                host_name,subn = host.split("/")

                ret_str += "[PSCustomObject]@{ BASE_HOST = " + host_name + "; SUBN = " + subn + "; RESOLV = "
                if host_name.replace(".", "").isnumeric():
                    ret_str += "$false },"
                else:
                    ret_str += "$true },"
            else:
                ret_str += "[PSCustomObject]@{ BASE_HOST = " + host + "; SUBN = 32; RESOLV = "
                if host.replace(".", "").isnumeric():
                    ret_str += "$false },"
                else:
                    ret_str += "$true },"

        ret_str = ret_str[:-1] + ")"

        return ret_str



class RequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args):
        self.cur_arg = Argument()
        BaseHTTPRequestHandler.__init__(self, *args)

    def collect_script(self, arg_str):
        return self.cur_arg.process_args(arg_str)

    def do_GET(self):
        query = urlparse(self.path).query
        query_components = dict(qc.split("=") for qc in query.split("&"))
        if len(query_components) <= 0 or "args" not in query_components:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"no args\n")
        else:
            query_str = decode(query_components['args'])
            print(f"Query string: {query_str}")
            if len(query_str) > 0:
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(encode(self.collect_script(query_str)).encode())
            else:
                self.send_response(404)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"no args\n")


def run_server(server_class=HTTPServer, handler_class=RequestHandler, port=8000):
    server_addr = ('', port)
    httpd = server_class(server_addr, handler_class)
    httpd.serve_forever()


if __name__ == "__main__":
    import pdb
    run_server()
