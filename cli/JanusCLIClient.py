#!/usr/bin/python3.6
import argparse
from getpass import getpass
import cmd2
from colorama import Fore
from utils import StaticContent
import rpyc


class Cli(cmd2.Cmd):

    """This is the CLI for Janus_IPv6"""
    intro = Fore.LIGHTRED_EX + StaticContent.INTRO_ART2 + StaticContent.INTRO
    prompt = Fore.GREEN + StaticContent.PROMPT + Fore.LIGHTWHITE_EX

    def __init__(self, host="localhost", port=12160, ipv6=True):
        cmd2.Cmd.__init__(self, persistent_history_file="./cmd_history.dat", persistent_history_length=1000)
        self.enable_ipv6 = ipv6
        self.host = host  # equal to '::1' for 'localhost', if ipv6 is enabled
        self.port = port
        self.conn = None
    conn_parser = argparse.ArgumentParser()
    conn_mutex = conn_parser.add_mutually_exclusive_group()
    conn_mutex.add_argument("-ip", "--ipaddress", metavar="<ip address>",
                            help="provide ip address to connect to server", type=str)
    conn_mutex.add_argument("-d", "--default", help="connect to default (localhost) server", action='store_true')

    @cmd2.with_argparser(conn_parser)
    def do_connect(self, args):
        """This is used to connect to the server"""
        # write password to stream, instead of stdout (hide on screen)
        password = getpass()

        if self.conn is None:
            try:
                if args.ipaddress:
                    self.conn = rpyc.connect(args.ipaddress, self.port, ipv6=self.enable_ipv6)
                elif args.default:
                    self.conn = rpyc.connect(self.host, self.port, ipv6=self.enable_ipv6)
                verification_msg = "Connected to " + Fore.CYAN + self.conn.root.get_service_name() + Fore.LIGHTWHITE_EX
                print(verification_msg)
            except ConnectionRefusedError:
                print("Server is not responding.")
        else:
            print("Already established connection to server. Re-run the application to connect to a different service.")

    # Top-Level parser for 'query' command
    query_parser = argparse.ArgumentParser()
    # Top-level positional argument
    query_parser.add_argument("db",
                              metavar="<database name>",
                              choices=["logs", "routing", "flows", "ruleset"],
                              help="provides access to the schema specified."
                                   "Schema names are: logs, routing, flows, ruleset.",
                              type=str)
    # Sub-parser container for sub-commands
    query_sp = query_parser.add_subparsers(help="Only one of these commands can be used", dest='subparser')

    # Sub-parser for 'select'
    select_parser = query_sp.add_parser('select', help="Used to select specific attributes, from a specific table.")
    select_parser.add_argument("-t", "--table", metavar="<table name>", required=True,
                               help="the table name to select from", type=str)
    select_parser.add_argument("-a", "--attributes", metavar="<attribute(s)>", nargs='+', required=True,
                               help="the attribute(s) to select.", type=str)

    # Sub-parser for 'custom' queries
    custom_parser = query_sp.add_parser('custom', help="Execute a custom query.")
    custom_parser.add_argument("query", metavar="<your query>", help="Execute a custom query")

    # Sub-parser to show tables of a schema, or attributes of a table
    show_parser = query_sp.add_parser('show', help="Show tables in schema, or describe a table.")
    show_parser_mutex = show_parser.add_mutually_exclusive_group()
    show_parser_mutex.add_argument("--show_tables", action="store_true",
                                   help="set this flag to show tables of specified schema")
    show_parser_mutex.add_argument("--describe", metavar="<table name>", type=str,
                                   help="use this flag to describe a table")
    show_parser_mutex.add_argument("--attributes", metavar="<table name>", type=str, help="show a table's attributes")

    @cmd2.with_argparser(query_parser)
    def do_query(self, args):

        """Used to query the repository"""

        if self.conn is None:
            print("Not connected to the server.\n(Use: <connect -d> to connect on the loopback i/face {::1}.)")
            return

        if args.subparser == 'custom':
            result = self.conn.root.custom_query(args.db, args.query)
            for col in result:
                print(col)

        elif args.subparser == 'select':
            result = self.conn.root.select(args.db, args.table, args.attributes)
            for col in result:
                print(col)

        elif args.subparser == 'show':
            if args.show_tables:
                result = self.conn.root.show_tables(args.db)
                for col in result:
                    print(col)
            elif args.describe:
                result = self.conn.root.describe_table(args.db, args.describe)
                for attr in result:
                    print(attr)
            elif args.attributes:
                result = self.conn.root.table_attributes(args.db, args.attributes)
                print(result)
