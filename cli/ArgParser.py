#!/usr/bin/python3.6

import argparse


# EXAMPLE OF ARGPARSE USAGE

def janus_parser():
    # instantiate parser
    parser = argparse.ArgumentParser()
    # add arg name (positional arg)
    # help variable, is to display argument usage
    parser.add_argument("-sq", "--square", help="display a square of a given number", type=int, action='my_action')
    args = parser.parse_args()
    if args.square:
        print(args.square ** 2)


def my_action():
    print("hello")
