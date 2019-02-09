#!/usr/bin/python3.6
import argparse
import cmd2
from colorama import Fore
from utils import art


class Cli(cmd2.Cmd):
    """This is the CLI for Janus_IPv6"""
    intro = Fore.LIGHTRED_EX + art.ALT_INTRO2 + 'You have entered the \'JanusIPv6\' interactive command-line ' \
                                                'interface.\nType \'?\' or \'help\'' \
                                                ' to see a list of the available commands.'
    prompt = Fore.GREEN + 'JanusIPv6 >>> ' + Fore.LIGHTWHITE_EX

    def __init__(self):
        cmd2.Cmd.__init__(self)

    # instantiate parser for mathematical functions (EXAMPLE)
    maths_parser = argparse.ArgumentParser()
    maths_parser.add_argument("-sq", "--square", help="display a number(input) squared", type=int)

    @cmd2.with_argparser(maths_parser)
    def do_math(self, args):
        """can be used to perform several math functions"""
        if args.square:
            print(args.square ** 2)
