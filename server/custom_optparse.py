#!/usr/bin/env python3

from copy import copy
from optparse import Option, OptionValueError

# a list of args must not have any spaces
def check_port_list(option, opt, value):
    try:
        val_lst = value.replace(" ", "").split(',')
        ret_lst = []
        for p in val_lst:
            if '-' in p:
                p_lst = p.split("-")
                # if the element is a range, add a tuple with the range bounds
                ret_lst.append((int(p_lst[0]), int(p_lst[1])))
            else:
                ret_lst.append(int(p))
        return ret_lst
    except Exception:
        raise OptionValueError("option %s: invalid list value: %r" % (opt, value))

# we will not support ranged ips: 192.168.0-255.1-255
# domain names must not have slashes: slashes are only used to designate subnets
def check_host_list(option, opt, value):
    try:
        val_lst = value.replace(" ", "").split(',')
        ret_lst = []
        for p in val_lst:
            if '/' in p:
                p_lst = p.split("/")
                # if the element has a subnet, convert it to an int
                ret_lst.append(p_lst[0], int(p_lst[1]))
            else:
                ret_lst.append((int(p), 0))
        return ret_lst
    except Exception:
        raise OptionValueError("option %s: invalid list value: %r" % (opt, value))

class ShellMapOption (Option):
    TYPES = Option.TYPES + ("port_list",)# + ("host_list",)
    TYPE_CHECKER = copy(Option.TYPE_CHECKER)
    TYPE_CHECKER["port_list"] = check_port_list
    #TYPE_CHECKER["host_list"] = check_host_list
