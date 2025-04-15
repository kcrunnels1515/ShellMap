# import all functions from http.server module
import socket
import sys
import traceback
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
server_address = "127.0.0.1"

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
        self.get_vars = dict()
        # map between modules and the variables they set
        self.set_vars = dict()
        # map between variables and default values
        self.def_vars = dict()
        # map between modules and the modules they conflict with
        self.conflicts = dict()
        # declare parser with custom argument parsing options
        self.parser = OptionParser(option_class=co.ShellMapOption)
        self.load_parser_rules()
        # creates a mapping between functional modules and their corresponding files
        self.modules = dict([ (Path(f.path).stem, f.path) for f in os.scandir(os.path.join(os.getcwd(), "modules")) if f.is_file() ])
        self.load_dependencies()

    def load_parser_rules(self):
        # options that add data
        self.parser.add_option("--p", action="store", type="port_list", dest="ports")
        self.parser.add_option("--PS", action="store", type="port_list", dest="ports_syn")
        self.parser.add_option("--PA", action="store", type="port_list", dest="ports_ack")
        self.parser.add_option("--PU", action="store", type="port_list", dest="ports_udp")
        self.parser.add_option("--PY", action="store", type="port_list", dest="ports_sctp")
        self.parser.add_option("--exclude-ports", action="store", type="port_list", dest="excluded_ports")
        self.parser.add_option("--top-ports", action="store", type="int", dest="top_ports")

        # options that modify behavior
        self.parser.add_option("--Pn", action="store_false", dest="host_disc", default=True)
        self.parser.add_option("--n", action="store_false", dest="resolve", default=True)
        self.parser.add_option("--F", action="store_true", dest="limit_ports", default=False)
        self.parser.add_option("--r", action="store_false", dest="randomize_ports", default=True)
        self.parser.add_option("--sV", action="store_true", dest="service_version", default=False)
        self.parser.add_option("--O", action="store_true", dest="os_detect", default=False)

        # options that store a string as their value are maps to a functional module
        # ex: these tell the fd determiner that it should add a particular module
        # host discovery methods
        self.parser.add_option("--PE", action="store_const", const="icmp_echo", dest="disc_method", default="ping_scan")
        self.parser.add_option("--PP", action="store_const", const="icmp_timestamp", dest="disc_method", default="ping_scan")
        self.parser.add_option("--PM", action="store_const", const="icmp_netmasq", dest="disc_method", default="ping_scan")
        self.parser.add_option("--sL", action="store_const", const="list_scan", dest="disc_method", default="ping_scan")
        self.parser.add_option("--sn", action="store_const", const="ping_scan", dest="disc_method", default="ping_scan")
        # port scanning methods
        self.parser.add_option("--sS", action="store_const", const="port_syn_scan", dest="default_scan", default="port_con_scan")
        self.parser.add_option("--sT", action="store_const", const="port_con_scan", dest="default_scan", default="port_con_scan")
        self.parser.add_option("--sA", action="store_const", const="port_ack_scan", dest="default_scan", default="port_con_scan")
        self.parser.add_option("--sU", action="store_const", const="port_udp_scan", dest="default_scan", default="port_con_scan")

    def load_dependencies(self):
        #breakpoint()
        with open('module_deps.txt', 'r') as deps:
            # reads a dependency file line by line
            # each line is of the format:
            #   A,B,C > [PROVIDED VARIABLE] < [REQUIRED VARIABLE1,[REQUIRED VARIABLE2, ...]]
            # where A is a module, and B and C are modules that A
            # depends on
            # PROVIDED VARIABLE is optional, provided if module A populates a variable
            # REQUIRED VARIABLES are optional, provided if module A requires the variables
            #
            # If a module does not use or set variables, the line would appear as:
            # A B C ><
            mods = []
            section = 0
            for line in deps:
                line = line.strip()

                if '#' in line:
                    continue

                if line == "===":
                    section = 1
                    continue
                if line == "+++":
                    section = 2
                    continue

                #breakpoint()
                match section:
                    case 0:
                        (var_name,val) = line.split('=', 1)
                        val = val.strip('"')
                        self.def_vars[var_name] = val
                    case 1:
                        #breakpoint()
                        (mods, write_var, read_vars) = re.split('>|<', line)
                        mod_lst = mods.split(',')

                        if len(mod_lst) == 1:
                            # no dependency
                            self.dependencies[mod_lst[0]] = []
                        else:
                            # has dependency
                            self.dependencies[mod_lst[0]] = mod_lst[1:]

                        # set variable names module needs to run
                        if len(read_vars) > 0:
                            read_lst = read_vars.split(',')
                            self.get_vars[mod_lst[0]] = read_lst
                        else:
                            self.get_vars[mod_lst[0]] = []

                        # set variable names that module populates
                        if len(write_var) > 0:
                            self.set_vars[mod_lst[0]] = write_var
                        else:
                            self.set_vars[mod_lst[0]] = ""
                    case 2:
                        (mod1, mod2) = line.split('^')
                        if mod1 in self.conflicts:
                            self.conflicts[mod1].append(mod2)
                        else:
                            self.conflicts[mod1] = [mod2]
                        if mod2 in self.conflicts:
                            self.conflicts[mod2].append(mod1)
                        else:
                            self.conflicts[mod2] = [mod1]
                    case _:
                        raise Exception('Something strange happened parsing modular deps')

    def process_args(self, arg_str):
        # string to hold all of the required script text
        script_str = ""
        # a general try-catch that will detect errors and return an error message
        try:
            # collect options and arguments from parsing the input
            # args should just be a list of hosts
            santi_args = self.sanitize_args(" " + arg_str).split(' ')
            #print(santi_args)
            try:
                (tmp_options, args) = self.parser.parse_args(santi_args)
            except:
                raise Exception("Could not understand your arguments")
            # interpret list of hosts as list of (host, subnet) pairs
            try:
                hosts = self.convert_targets(args)
            except:
                raise Exception("Could not understand your host descriptions")
            tmp_opt_dict = ast.literal_eval(str(tmp_options))
            # cleaned options, without false or Empty values
            opt_dict = dict([(k, v) for k, v in tmp_opt_dict.items() if v is not None])

            # collect required functional modules, and arguments to those functional modules
            fm_lst, opt_args = self.collect_modules(opt_dict, hosts)
            #breakpoint()
            # use mapping between fd names and modules to concatenate scripts
            for mod in fm_lst:
                with open(self.modules[mod], 'r') as mod_file:
                    script_str += mod_file.read() + "\n"

            # add option arguments and target specs to beginning as global variables
            # these are added afterwards to that functions can be retreived as variables
            for k, v in opt_args.items():
                script_str += f"${k.upper()} = {v}\n"

            with open('./main_execution.ps1', 'r') as main_loop:
                script_str += main_loop.read()
        except Exception as e:
            print(traceback.format_exc())
            script_str = f"Write-Host \"Encountered error processing: {e}\""

        return script_str

    def sanitize_args(self, arg_str):
        pat = re.compile(r"(?<=([^-\S]))-[^-]")
        pos = 0
        running_pos = 0
        short_args = []
        manip = list(arg_str)

        while m:= pat.search(arg_str, pos):
            pos = m.start() + 1
            short_args.append(m.span())

        for fst, snd in short_args:
            manip.insert(fst+running_pos, '-')
            running_pos += 1
        return ''.join(manip)

    def collect_modules(self, options, hosts):
        deps = []
        added = dict.fromkeys(self.dependencies.keys(), False)
        opt_args = {}
        #breakpoint()
        for k in options.keys():
            #print(f"Checking option {k}")
            #print(opt_args)
            if options[k] != False:
                self.fd_helper(k, deps, added, options)
            if isinstance(options[k], list):
                opt_args[self.set_vars[k]] = self.convert_portlist(options[k])
            elif isinstance(options[k], bool):
                opt_args[self.set_vars[k]] = "$" + str(options[k])
            elif isinstance(options[k], int):
                opt_args[self.set_vars[k]] = str(options[k])
            elif isinstance(options[k], str):
                opt_args[self.set_vars[k]] = f"Get-Item -Path 'Function:\\{options[k]}'"

        # append HOSTS variable to opt_args
        if len(hosts) > 0:
            opt_args['HOSTS'] = hosts
        #breakpoint()
        # set of variables that are set in arguments
        arg_vars = set(opt_args)

        # set of variables required by enabled modules
        needed_vars = set()
        for dep in deps:
            needed_vars.update(self.get_vars[dep])

        # construct a dict of variable-value pairs where
        # the value is used from the arguments if the variable
        # name is in the set of argument-provided variables
        # otherwise, pulls the value from the dict of default values
        full_var_args = dict([ (v, opt_args[v]) if v in arg_vars else (v, self.def_vars[v]) for v in needed_vars ])

        return (deps, full_var_args)

    def fd_helper(self, k, dep_lst, added_dict, opts):
        # some modules may not be present in options
        if k in opts:
            # if option holds a string, set the key to that string
            if isinstance(opts[k], str):
                #k = opts[k]
                self.fd_helper(opts[k], dep_lst, added_dict, opts)

        if added_dict[k]:
            return

        if k in self.conflicts:
            for conf_mod in self.conflicts[k]:
                if conf_mod in dep_lst:
                    raise Exception(f"Cannot use module {k} with module {conf_mod} enabled")

        # if a functional module has no dependencies add it
        if (len(self.dependencies[k]) == 0):
            dep_lst.append(k)
            added_dict[k] = True
        # otherwise if the module has dependencies, recursively add
        # the dependencies and then add the initial module
        else:
            for dep in self.dependencies[k]:
                self.fd_helper(dep, dep_lst, added_dict, opts)
            dep_lst.append(k)
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
        #
        # Ensure that host list was passed in
        empty_hosts = True
        for h in host_lst:
            if len(h) > 0:
                empty_hosts = False
                break
        if empty_hosts:
            return ""

        val_lst = "".join(host_lst).split(',')
        ret_str = "@("
        for host in val_lst:
            if '/' in host:
                # get subnet size
                host_name,subn = host.split("/")

                ret_str += "[PSCustomObject]@{ BASE_HOST = \"" + host_name + "\"; SUBN = " + subn + "; ADDR = $null; RESOLV = "
                if host_name.replace(".", "").isnumeric():
                    ret_str += "$false },"
                else:
                    ret_str += "$true },"
            else:
                ret_str += "[PSCustomObject]@{ BASE_HOST = \"" + host + "\"; SUBN = 32; ADDR = $null; RESOLV = "
                if host.replace(".", "").isnumeric():
                    ret_str += "$false },"
                else:
                    ret_str += "$true },"

        ret_str = ret_str[:-1] + ")"

        return ret_str



class RequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args):
        self.cur_arg = Argument()
        self.getter_script = ""
        self.encode_access()
        BaseHTTPRequestHandler.__init__(self, *args)

    def collect_script(self, arg_str):
        return self.cur_arg.process_args(arg_str)

    def encode_access(self):
        tmp_str = ""
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        i = 0

        with open("access_script.ps1", 'r') as f:
            tmp_str = f.read()
        tmp_str = tmp_str.replace('IP_ADDR_HERE', server_address)
        for char in tmp_str:
            self.getter_script += char
            self.getter_script += alphabet[i%len(alphabet)]
            i += 1

    def do_GET(self):
        query = urlparse(self.path).query
        query_components = dict(qc.split("=") for qc in query.split("&"))
        if len(query_components) <= 0:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"no args\n")
        elif "args" in query_components:
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
        elif "gimme" in query_components:
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(bytearray(self.getter_script, 'ascii'))

def run_server(server_class=HTTPServer, handler_class=RequestHandler, port=8000):
    server_addr = ('', port)
    httpd = server_class(server_addr, handler_class)
    httpd.serve_forever()


if __name__ == "__main__":
    import pdb
    if len(sys.argv) > 1:
        try:
            server_host = urlparse("http://" + sys.argv[1])
            if len(server_host.netloc) > 0:
                server_address = server_host.netloc
            else:
                raise Exception
        except:
            print(f"Invalid host IP address {sys.argv[1]}, exiting")
            exit(1)
    try:
        run_server()
    except Exception as e:
        print(f"Encountered an exception: {e}")
