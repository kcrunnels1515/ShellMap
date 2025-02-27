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
                port = int(p_lst[0])
                rng = int(p_lst[1]) - port
                # if the element is a range, add a tuple with the range bounds
                ret_lst.append((port, rng))
            else:
                ret_lst.append((int(p), 0))
        return ret_lst
    except Exception:
        raise OptionValueError("option %s: invalid list value: %r" % (opt, value))

class ShellMapOption (Option):
    TYPES = Option.TYPES + ("port_list",)
    TYPE_CHECKER = copy(Option.TYPE_CHECKER)
    TYPE_CHECKER["port_list"] = check_port_list
    #TYPE_CHECKER["host_list"] = check_host_list
