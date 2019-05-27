#!/usr/bin/python3.6
import argparse
import cmd2
from colorama import Fore
from utils import static
import socket


SERVER_ADDRESS = '127.0.0.1'  # address that the server listens to. (Loopback interface for local execution)
PORT = 12160  # port address that the server uses
ENCODING = 'utf-8'  # the encoding of the characters to be used by client


class Cli(cmd2.Cmd):
    """This is the CLI for Janus_IPv6"""
    intro = Fore.LIGHTRED_EX + static.INTRO_ART2 + static.INTRO
    prompt = Fore.GREEN + static.PROMPT + Fore.LIGHTWHITE_EX

    def __init__(self, host=SERVER_ADDRESS, port=PORT, enc=ENCODING):
        cmd2.Cmd.__init__(self)
        self.host = host
        self.port = port
        self.encoding = enc

    # instantiate parser for mathematical functions (EXAMPLE)
    maths_parser = argparse.ArgumentParser()
    maths_parser.add_argument("-sq", "--square", help="display a number(input) squared", type=int)

    @cmd2.with_argparser(maths_parser)
    def do_math(self, args):
        """can be used to perform several math functions"""
        if args.square:
            print(args.square ** 2)

    test_parser = argparse.ArgumentParser()
    test_parser.add_argument("-t", "--test", help="Will send typed message to the server")

    @cmd2.with_argparser(test_parser)
    def do_test_con(self, args):
        """used to test connection between client-server"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_ADDRESS, PORT))
            s.sendall(bytes(args.test, ENCODING))
            data = s.recv(4096)
            print('SERVER REPLIED > ', data.decode(ENCODING))
