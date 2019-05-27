#!/usr/bin/python3.6
from subprocess import call
import argparse

'''
For simplicity, this file is also copied in "usr/local/bin", so that it can be run from any directory
by simply calling: add_ipv6 <hostname> <ipv6>.

The file in "usr/local/bin" is renamed to 'add_ipv6' (no ".py" file extension)
'''


add_ipv6_cmd = "ifconfig h{hostname}-eth0 inet6 add 2000::{ip}/64"
add_ipv6_dist_global = "ifconfig h{hostname}-eth0 inet6 add 200{ip}::{ip}/64"
add_ipv6_custom_cmd = "ifconfig h{hostname}-eth0 inet6 add {ip}/64"

parser = argparse.ArgumentParser(description="Add an IPv6 GUA, to the eth0 interface")
parser.add_argument("hostname",
                    help="Add the number of the host. e.g: if host is 'h4', enter: 4",
                    type=int)

mutex = parser.add_mutually_exclusive_group()

# mutex.add_argument("-d","--distinct",
#                     help="add a different IPv6 GUA for this node",
#                     action=store_true)

mutex.add_argument("-c", "--custom", help="Add a custom IPv6 GUA.", type=str)

args = parser.parse_args()

# if args.distinct:
#     command = add_ipv6_dist_global.format(hostname=args.hostname,
#                                         ip=args.hostname)
if args.custom:
    command = add_ipv6_custom_cmd.format(hostname=args.hostname, ip=args.custom)
else:
    command = add_ipv6_cmd.format(hostname=args.hostname, ip=args.hostname)

print("Executing command: "+command)
call(command.split(" "))
print("IPv6 address added successfully.")
