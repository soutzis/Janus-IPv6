import argparse


def get_connection_parser():
    # Parser for connection to repository server
    conn_parser = argparse.ArgumentParser()
    conn_mutex = conn_parser.add_mutually_exclusive_group()
    conn_mutex.add_argument("-ip", "--ipaddress",
                            metavar="<ip address>",
                            help="provide ip address to connect to server",
                            type=str)
    conn_mutex.add_argument("-d", "--default",
                            help="connect to the default server (localhost)",
                            action="store_true")

    return conn_parser


def get_query_parser():
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
    query_sp = query_parser.add_subparsers(help="Only one of these commands can be used:", dest='subparser')

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
    show_parser_mutex.add_argument("--table_attributes", metavar="<table name>", type=str,
                                   help="Show just the table's attributes (alternative of describe)")

    return query_parser


def get_rule_parser():
    rule_parser = argparse.ArgumentParser()
    r1_mutex = rule_parser.add_mutually_exclusive_group()
    r1_mutex.add_argument("-a", "--add",
                          action="store_true",
                          help="allows a user to add a new blacklisting rule"
                          )

    r1_mutex.add_argument("-m", "--modify",
                          action="store_true",
                          help="modify an existing blacklisting rule"
                          )

    r1_mutex.add_argument("-s", "--show",
                          action="store_true",
                          help="show blacklist rule descriptions"
                          )
    return rule_parser
