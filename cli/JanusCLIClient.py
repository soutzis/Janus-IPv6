#!/usr/bin/python3.6
import argparse
from datetime import datetime

import cmd2
import rpyc

from getpass import getpass
from cmd2 import with_argparser, categorize
from cmd2.argparse_completer import ACArgumentParser
from colorama import Fore
from tabulate import tabulate

from cli import CommandParsers
from utils.static import CMD_CATEGORY_CONNECTION, CMD_CATEGORY_DATABASE, CMD_CATEGORY_MONITOR, \
    PROMPT, INTRO_ART2, INTRO, NOT_CONNECTED_ERROR, CMD_CATEGORY_RULES


class Cli(cmd2.Cmd):

    """This is the CLI for Janus_IPv6"""

    intro = Fore.LIGHTRED_EX + INTRO_ART2 + INTRO
    prompt = Fore.GREEN + PROMPT + Fore.LIGHTWHITE_EX

    # --------------------------------------------------------------- #
    # Below are the command parsers, used by the CLI.                 #
    # Next to them, the command they are responsible for, is included #
    # --------------------------------------------------------------- #
    conn_parser = CommandParsers.get_connection_parser()  # connect
    query_parser = CommandParsers.get_query_parser()  # query
    rule_parser = CommandParsers.get_rule_parser()  # rule

    def __init__(self, host="::1", port=12160, ipv6=True):
        cmd2.Cmd.__init__(self,
                          persistent_history_file="/home/soutzis/PycharmProjects/Janus_IPv6/utils/cmd_history.dat",
                          persistent_history_length=1000)
        self.schema_names = {
            "logs": "Logs",
            "flows": "NetworkFlows",
            "routing": "Routing",
            "ruleset": "Rulesets"
        }
        self.enable_ipv6 = ipv6
        self.host = host  # equal to '::1' for 'localhost', if ipv6 is enabled
        self.port = port
        self.conn = None

    # Every function that has the "do_" prefix, is a command of the CLI

    @with_argparser(ACArgumentParser())
    def do_quit(self, _: argparse.Namespace) -> bool:
        """Exit this application and close connection with server if there is one."""
        if self.conn is not None:
            self.conn.close()
        self._should_quit = True
        return self._STOP_AND_EXIT

    @cmd2.with_argparser(conn_parser)
    def do_connect(self, args):
        """This command is used to connect to the Janus Repository"""
        if self.conn is None:
            try:
                if args.ipaddress:
                    self.conn = rpyc.connect(args.ipaddress, self.port,
                                             ipv6=self.enable_ipv6,
                                             config={"allow_all_attrs": True})
                elif args.default:
                    self.conn = rpyc.connect(self.host, self.port,
                                             ipv6=self.enable_ipv6,
                                             config={"allow_all_attrs": True})
                else:
                    print("Please use \'-d\' or \'-ip\' flag, to specify IP address of server.")
                    print("Use \"$ connect -h\" for more information.")
                    return

                # Authenticate client
                if self._validate_admin():
                    verification_msg = "Connected to "+Fore.CYAN+self.conn.root.get_service_name()+Fore.LIGHTWHITE_EX
                    print(verification_msg)
                # Else, if the authentication was unsuccessful, disconnect from server.
                else:
                    self.conn.close()
                    self.conn = None
            except ConnectionRefusedError:
                print("Server is not responding.")
        else:
            print(
                "Already established connection to server.\n"
                "Re-run the application to connect to a different service."
            )

    @cmd2.with_argparser(rule_parser)
    def do_rule(self, args):
        """
        This method is used to create, modify or just view the 'blacklist' ruleset of Janus
        """
        if self.conn is None:
            print(NOT_CONNECTED_ERROR)
            return
        else:
            server_api = self.conn.root
            ruleset = server_api.get_ruleset()

        if args.add:
            try:
                new_rule = self._add_new_rule()
                # Length should be at least or larger than 3 (action, description, priority are mandatory, but useless)
                if len(new_rule) >= 3:
                    ruleset['blacklist'].append(new_rule)
                    server_api.update_ruleset(ruleset)
                else:
                    print("There was not sufficient information to add this rule.")
            except KeyboardInterrupt:
                print("\nOperation aborted")

        elif args.modify:
            self._show_rule_descriptions(ruleset)
            selection_num = self._select_rule("\nEnter the # of the rule you would like to modify.", ruleset)
            rule = ruleset['blacklist'][selection_num]
            mod_rule = self._modify_rule(rule)
            ruleset['blacklist'][selection_num] = mod_rule
            server_api.update_ruleset(ruleset)

        elif args.show:
            self._show_rule_descriptions(ruleset)
            selection_num = self._select_rule("\nEnter the # of the rule you would like to view.", ruleset)
            self._show_rule(ruleset['blacklist'][selection_num])

    @cmd2.with_argparser(query_parser)
    def do_query(self, args):

        """Used to query the repository"""

        if self.conn is None:
            print(NOT_CONNECTED_ERROR)
            return
        else:
            server_api = self.conn.root

        if args.subparser == 'custom':
            result = server_api.custom_query(args.db, args.query)
            result = self._transform_datetime_in_list(result)
            # Formulate result as tabular data, first row is attribute names (column names)
            tabular_result = tabulate(result, headers="firstrow", tablefmt="psql")
            print(tabular_result)

        elif args.subparser == 'select':
            # Here, args.attributes is a list, containing the attributes specified through the CLI
            result = server_api.select(args.db, args.table, args.attributes)
            result = self._transform_datetime_in_list(result)
            tabular_result = tabulate(result, headers=args.attributes, tablefmt="psql")
            print(tabular_result)

        elif args.subparser == 'show':
            # This will be the object printed to the client
            tabular_result = ""

            if args.show_tables:
                result = server_api.show_tables(args.db)  # Get tables of specified schema
                result = self._transform_datetime_in_list(result)
                attrs = [self.schema_names[args.db]]
                tabular_result = tabulate(result, headers=attrs, tablefmt="psql")

            elif args.describe:
                result = server_api.describe_table(args.db, args.describe)
                result = self._transform_datetime_in_list(result)
                attrs = ['Field', 'Type', 'Null', 'Key', 'Default', 'Extra']
                tabular_result = tabulate(result, headers=attrs, tablefmt="psql")

            elif args.table_attributes:
                result = server_api.table_attributes(args.db, args.table_attributes)
                result = self._transform_datetime_in_list(result)
                attrs = [args.table_attributes]
                tabular_result = tabulate(result, headers=attrs, tablefmt="psql")

            print(tabular_result)

    @with_argparser(ACArgumentParser())
    def do_disconnect(self, _: argparse.Namespace):
        """Call this to disconnect from the repository"""
        if self.conn is None:
            print("You are not connected to the repository")
        else:
            self.conn.close()
            self.conn = None
            print("Disconnected.")

    @with_argparser(ACArgumentParser())
    def do_monitor(self, _: argparse.Namespace):
        """
        This command will initiate a monitoring state, where the client will receive alerts about events
        from the controller
        """

        if self.conn is None:
            print(NOT_CONNECTED_ERROR)
            return
        else:
            server_api = self.conn.root

        db = 'logs'
        table = 'log_records'
        dtime = datetime.now()
        log_id = None

        # Get the attribute names, by querying the server for them
        attrs = server_api.table_attributes(db, table)
        attrs = [item for sublist in attrs for item in sublist]  # flatten lists into 1 list

        # Make all attribute names BOLD, so that it looks cute in the CLI
        for i in range(len(attrs)):
            attrs[i] = '\033[1m' + attrs[i] + '\033[0m'

        while True:
            try:
                result = server_api.monitor(dtime, log_id)
                if result is None:
                    continue
                else:
                    record = self._transform_datetime_in_list(list(result[0]))
                    log_id = record[0]
                    tabular_data = [record]
                    print(tabulate(tabular_data, headers=attrs, tablefmt="psql", numalign="center", stralign="center"))

            # The only way for user to exit Active Monitoring, is to use the keyboard shortcut: "CTRL + C"
            # Thus, when a 'Keyboard Interrupt' is detected, inform the server that it should turn-off this mode.
            except KeyboardInterrupt:
                print("\rActive Monitoring Mode exited!")
                return

    def _validate_admin(self) -> bool:
        """
        This function will contact the server to log the administrator in.
        :return: True if the user entered the right password, or false if the user entered the wrong password 3 times.
        """
        max_attempts = 3
        incorrect_attempts = 0
        is_admin = False

        while incorrect_attempts < max_attempts and is_admin is False:
            # write password to stream, instead of stdout (hide from UI)
            password = getpass()
            # contact server to authenticate
            is_admin = self.conn.root.authenticate_admin(password)
            if is_admin:
                return True
            else:
                incorrect_attempts += 1
                if incorrect_attempts < max_attempts:
                    print("Sorry, try again.")

        print("{} incorrect attempts.".format(incorrect_attempts))

        return False

    @staticmethod
    def _select_rule(instruction, ruleset):
        """
        :param instruction: The instruction to print to terminal
        :param ruleset: The ruleset to choose a rule from
        :return: An integer that characterizes the selection index
        """
        print(instruction)
        selection_num = None
        while selection_num is None:
            try:
                selection_num = int(input('#: '))
                if selection_num not in range(len(ruleset['blacklist'])):
                    selection_num = None
                    print("Selection needs to be one of the indexes, shown in the above table.")
            except ValueError:
                selection_num = None
                print("You need to enter a numerical value.\n")
        return selection_num

    @staticmethod
    def _show_rule(rule: dict):
        """
        Displays a given rule to the terminal
        :param rule: The rule to display
        """
        description = rule.pop('description')
        print("\nRULE: " + description)
        attrs = list(rule.keys())
        data = [list(rule.values())]
        print(tabulate(data, headers=attrs, tablefmt='github'))

    @staticmethod
    def _show_rule_descriptions(ruleset):
        """
        This method will display all the rules along with their indices, in a given ruleset.
        :param ruleset: The ruleset to view the rules of
        """
        index = 0
        attrs = ['#', 'Description']
        data = []
        for rule in ruleset['blacklist']:
            row = [index, rule['description']]
            data.append(row)
            index += 1
        print(tabulate(data, headers=attrs, tablefmt='fancy_grid'))

    @staticmethod
    def _transform_datetime_in_list(tabular_data):
        """
        This function is necessary, to convert datetime objects, into their string representation, so that they
        can be printed to the terminal with the "tabulate()" module.
        :param tabular_data: Is the data returned from the database query. The data could be a list, a list of lists,
        a tuple of tuples, a list of tuples, etc.
        :return: The data that was passed as a parameter, but with any datetime elements converted to a string.
        """

        # Conditional checks are to determine if this is a single record, or a collection of records.
        if any((isinstance(i, list) or isinstance(i, tuple)) for i in tabular_data):
            for x in range(len(tabular_data)):
                # convert any datetime objects to string, to avoid an unexpected AttributeError (in tabulate.py)
                for i in range(len(tabular_data[x])):
                    if isinstance(tabular_data[x][i], datetime):
                        tabular_data[x][i] = tabular_data[x][i].strftime("%d/%m/%Y, %H:%M:%S")
        else:
            # convert any datetime objects to string, to avoid an unexpected AttributeError (in tabulate.py)
            for i in range(len(tabular_data)):
                if isinstance(tabular_data[i], datetime):
                    tabular_data[i] = tabular_data[i].strftime("%d/%m/%Y, %H:%M:%S")

        return tabular_data

    def _get_binary_input(self, question: str) -> bool:
        """
        :param question: The question to display in the terminal
        :return: The user's answer (YES or NO)
        """
        print(question)
        answer = input('Answer [Y/N]: ')

        if answer.lower() == "y":
            return True
        elif answer.lower() == "n":
            return False
        else:
            print("Please use 'Y' for 'YES' and 'N' for 'NO'. The input is not case-sensitive.")
            return self._get_binary_input(question)

    def _modify_rule(self, rule):
        """
        :param rule: The rule to modify
        :return: The modified rule
        """
        min_priority = 1
        max_priority = 65535
        has_ethertype = False
        ip_proto = None

        print("Follow the instructions to modify the selected rule.\nTo quit, press \"CTRL + C\".")

        # ADD DESCRIPTION
        if self._get_binary_input("\nModify the rule description?"):
            description = input('Description: ')
            rule['description'] = description

        # ADD RULE PRIORITY
        if self._get_binary_input("\nModify the rule priority?"):
            priority = None
            while priority is None and priority not in range(min_priority, max_priority + 1):
                print("The priority has to be in the range 1-65535.")
                try:
                    priority = int(input('Priority: '))
                except ValueError:
                    priority = None
                    print("You need to enter a numerical value between 1-65535.\n")
            rule['priority'] = priority

        # ADD SWITCH INPUT PORT
        if 'in_port' in rule:
            if self._get_binary_input("\nModify the incoming port number?"):
                in_port = None
                while in_port is None:
                    try:
                        in_port = int(input('In_port: '))
                    except ValueError:
                        in_port = None
                        print("You need to enter a numerical value.\n")
                rule['in_port'] = in_port
        else:
            if self._get_binary_input("\nAdd the incoming port number?"):
                in_port = None
                while in_port is None:
                    try:
                        in_port = int(input('In_port: '))
                    except ValueError:
                        in_port = None
                        print("You need to enter a numerical value.\n")
                rule['in_port'] = in_port

        # ADD MAC SOURCE
        if 'eth_src' in rule:
            if self._get_binary_input("\nModify source MAC address?"):
                eth_src = input('Source MAC address: ')
                rule['eth_src'] = eth_src
        else:
            if self._get_binary_input("\nAdd source MAC address?"):
                eth_src = input('Source MAC address: ')
                rule['eth_src'] = eth_src

        # ADD MAC DEST
        if 'eth_dst' in rule:
            if self._get_binary_input("\nModify destination MAC address?"):
                eth_dst = input('Destination MAC address: ')
                rule['eth_dst'] = eth_dst
        else:
            if self._get_binary_input("\nAdd destination MAC address?"):
                eth_dst = input('Destination MAC address: ')
                rule['eth_dst'] = eth_dst

        # ADD ETHER_TYPE
        if 'eth_type' in rule:
            has_ethertype = True
            if self._get_binary_input("\nModify ethernet packet type?"):
                has_ethertype = True
                attrs = ['ARP', 'IPv4', 'IPv6']
                data = [[2054, 2048, 34525]]
                print("Use one of the specified values below\n")
                print(tabulate(data, headers=attrs, tablefmt='fancy_grid'))

                eth_type = None
                while eth_type is None:
                    try:
                        eth_type = int(input('Ethertype: '))
                        if eth_type not in data[0]:
                            eth_type = None
                            print("Ethertype needs to be one of the specified values in the above table.")
                    except ValueError:
                        eth_type = None
                        print("You need to enter a numerical value.\n")
                rule['eth_type'] = eth_type
        else:
            if self._get_binary_input("\nAdd ethernet packet type?\n"
                                      "NOTE: This is required, in order to specify network or transport layer fields."):
                has_ethertype = True
                attrs = ['ARP', 'IPv4', 'IPv6']
                data = [[2054, 2048, 34525]]
                print("Use one of the specified values below\n")
                print(tabulate(data, headers=attrs, tablefmt='fancy_grid'))

                eth_type = None
                while eth_type is None:
                    try:
                        eth_type = int(input('Ethertype: '))
                        if eth_type not in data[0]:
                            eth_type = None
                            print("Ethertype needs to be one of the specified values in the above table.")
                    except ValueError:
                        eth_type = None
                        print("You need to enter a numerical value.\n")
                rule['eth_type'] = eth_type

        # PROMPT USER TO ADD IP ADDRESS, ONLY IF ETHERTYPE WAS SPECIFIED
        if has_ethertype:

            # ADD SOURCE IPv6
            if 'ipv6_src' in rule:
                if self._get_binary_input("\nModify existing source IP address?"):
                    ipv6_src = input('Source IP address: ')
                    rule['ipv6_src'] = ipv6_src
            else:
                if self._get_binary_input("\nAdd source IP address?"):
                    ipv6_src = input('Source IP address: ')
                    rule['ipv6_src'] = ipv6_src

            # ADD DESTINATION IPv6
            if 'ipv6_dst' in rule:
                if self._get_binary_input("\nModify destination IP address?"):
                    ipv6_dst = input('Destination IP address: ')
                    rule['ipv6_dst'] = ipv6_dst
            else:
                if self._get_binary_input("\nAdd destination IP address?"):
                    ipv6_dst = input('Destination IP address: ')
                    rule['ipv6_dst'] = ipv6_dst

            # ADD TRANSPORT LAYER PROTOCOL
            if 'ip_proto' in rule:
                ip_proto = rule['ip_proto']
                if self._get_binary_input("\nChange transport-layer protocol?"):
                    ip_proto = None  # Change to null, so that the user can enter a new value
                    attrs = ['TCP', 'UDP', 'ICMPv6', 'SCTP', 'NONE']
                    data = [[6, 17, 58, 132, 59]]
                    print("Use one of the specified values below\n")
                    print(tabulate(data, headers=attrs, tablefmt='fancy_grid'))

                    while ip_proto is None:
                        try:
                            ip_proto = int(input('Protocol: '))
                            if ip_proto not in data[0]:
                                ip_proto = None
                                print("Protocol needs to be one of the specified values in the above table.")
                        except ValueError:
                            ip_proto = None
                            print("You need to enter a numerical value.\n")
                    rule['ip_proto'] = ip_proto
            else:
                if self._get_binary_input("\nSpecify transport-layer protocol?\n"
                                          "NOTE: This is required, in order to specify transport layer fields."):
                    attrs = ['TCP', 'UDP', 'ICMPv6', 'SCTP', 'NONE']
                    data = [[6, 17, 58, 132, 59]]
                    print("Use one of the specified values below\n")
                    print(tabulate(data, headers=attrs, tablefmt='fancy_grid'))

                    while ip_proto is None:
                        try:
                            ip_proto = int(input('Protocol: '))
                            if ip_proto not in data[0]:
                                ip_proto = None
                                print("Protocol needs to be one of the specified values in the above table.")
                        except ValueError:
                            ip_proto = None
                            print("You need to enter a numerical value.\n")
                    rule['ip_proto'] = ip_proto

        # TCP
        if ip_proto == 6:
            # TCP SOURCE PORT
            if self._get_binary_input("\nEdit source port number?"):
                tcp_src = None
                while tcp_src is None:
                    try:
                        tcp_src = int(input('Source port: '))
                        if tcp_src not in range(1, 65536):
                            tcp_src = None
                            print("Port needs to be in the range of valid port numbers (1-65535).")
                    except ValueError:
                        tcp_src = None
                        print("You need to enter a numerical value.\n")
                rule['tcp_src'] = tcp_src

            # TCP DESTINATION PORT
            if self._get_binary_input("\nEdit destination port number?"):
                tcp_dst = None
                while tcp_dst is None:
                    try:
                        tcp_dst = int(input('Destination port: '))
                        if tcp_dst not in range(1, 65536):
                            tcp_dst = None
                            print("Port needs to be in the range of valid port numbers (1-65535).")
                    except ValueError:
                        tcp_dst = None
                        print("You need to enter a numerical value.\n")
                rule['tcp_dst'] = tcp_dst

        # UDP
        elif ip_proto == 17:
            # UDP SOURCE PORT
            if self._get_binary_input("\nEdit source port number?"):
                udp_src = None
                while udp_src is None:
                    try:
                        udp_src = int(input('Source port: '))
                        if udp_src not in range(1, 65536):
                            udp_src = None
                            print("Port needs to be in the range of valid port numbers (1-65535).")
                    except ValueError:
                        udp_src = None
                        print("You need to enter a numerical value.\n")
                rule['udp_src'] = udp_src

            # UDP DESTINATION PORT
            if self._get_binary_input("\nEdit destination port number?"):
                udp_dst = None
                while udp_dst is None:
                    try:
                        udp_dst = int(input('Destination port: '))
                        if udp_dst not in range(1, 65536):
                            udp_dst = None
                            print("Port needs to be in the range of valid port numbers (1-65535).")
                    except ValueError:
                        udp_dst = None
                        print("You need to enter a numerical value.\n")
                rule['udp_dst'] = udp_dst

        # ICMPv6
        elif ip_proto == 58:
            # TYPE
            if self._get_binary_input("\nEdit ICMPv6 type?"):
                attrs = ['Type Description', 'Type Value']
                data = [
                    ['Destination Unreachable', 1],
                    ['Packet Too Big', 2],
                    ['Time Exceeded', 3],
                    ['Parameter Problem', 4],
                    ['Echo Request', 128],
                    ['Echo Reply', 129],
                    ['Router Solicitation', 133],
                    ['Router Advertisement', 134],
                    ['Neighbor Solicitation', 135],
                    ['Neighbor Advertisement', 136],
                    ['Redirect', 137]
                ]
                print("Use one of the specified values below, for ICMPv6 type\n")
                print(tabulate(data, headers=attrs, tablefmt='fancy_grid'))
                icmpv6_type = None
                while icmpv6_type is None:
                    try:
                        icmpv6_type = int(input('Type: '))
                        if icmpv6_type not in [item for sublist in data for item in sublist]:
                            icmpv6_type = None
                            print("Type needs to be one of the valid types shown in the above table.")
                    except ValueError:
                        icmpv6_type = None
                        print("You need to enter a numerical value.\n")
                rule['icmpv6_type'] = icmpv6_type

            # CODE
            if self._get_binary_input("\nEdit ICMPv6 code?"):
                icmpv6_code = None
                while icmpv6_code is None:
                    try:
                        icmpv6_code = int(input('Code: '))
                    except ValueError:
                        icmpv6_code = None
                        print("You need to enter a numerical value.\n")
                rule['icmpv6_code'] = icmpv6_code

        # Finally, return the new rule (as a dict)
        return rule

    def _add_new_rule(self):
        """
        This method will guide the user, to create a new blocking rule for Janus.
        :return: A new rule to be added to the blacklist ruleset of the repository
        """
        new_rule = {"action": "drop"}
        min_priority = 1
        max_priority = 65535
        has_ethertype = False
        ip_proto = None

        print("Follow the instructions to add a new 'blocking' rule.\nTo quit, press \"CTRL + C\".")

        # ADD DESCRIPTION
        print("\nAdd a description for uniquely identifying this rule and press \"Enter\".")
        description = input('Description: ')
        new_rule['description'] = description

        # ADD RULE PRIORITY
        print("\nAdd priority of this rule, over the rest of the rules.")
        priority = None
        while priority is None and priority not in range(min_priority, max_priority + 1):
            print("The priority has to be in the range 1-65535.")
            try:
                priority = int(input('Priority: '))
            except ValueError:
                priority = None
                print("You need to enter a numerical value between 1-65535.\n")
        new_rule['priority'] = priority

        # ADD SWITCH INPUT PORT
        if self._get_binary_input("\nAdd the incoming port number?"):
            in_port = None
            while in_port is None:
                try:
                    in_port = int(input('In_port: '))
                except ValueError:
                    in_port = None
                    print("You need to enter a numerical value.\n")
            new_rule['in_port'] = in_port

        # ADD MAC SOURCE
        if self._get_binary_input("\nAdd source MAC address?"):
            eth_src = input('Source MAC address: ')
            new_rule['eth_src'] = eth_src

        # ADD MAC DEST
        if self._get_binary_input("\nAdd destination MAC address?"):
            eth_dst = input('Destination MAC address: ')
            new_rule['eth_dst'] = eth_dst

        # ADD ETHER_TYPE
        if self._get_binary_input("\nAdd ethernet packet type?\n"
                                  "NOTE: This is required, in order to specify network or transport layer fields."):
            has_ethertype = True
            attrs = ['ARP', 'IPv4', 'IPv6']
            data = [[2054, 2048, 34525]]
            print("Use one of the specified values below\n")
            print(tabulate(data, headers=attrs, tablefmt='fancy_grid'))

            eth_type = None
            while eth_type is None:
                try:
                    eth_type = int(input('Ethertype: '))
                    if eth_type not in data[0]:
                        eth_type = None
                        print("Ethertype needs to be one of the specified values in the above table.")
                except ValueError:
                    eth_type = None
                    print("You need to enter a numerical value.\n")
            new_rule['eth_type'] = eth_type

        # PROMPT USER TO ADD IP ADDRESS, ONLY IF ETHERTYPE WAS SPECIFIED
        if has_ethertype:
            if self._get_binary_input("\nAdd source IP address?"):
                ipv6_src = input('Source IP address: ')
                new_rule['ipv6_src'] = ipv6_src

            if self._get_binary_input("\nAdd destination IP address?"):
                ipv6_dst = input('Destination IP address: ')
                new_rule['ipv6_dst'] = ipv6_dst

            if self._get_binary_input("\nSpecify transport-layer protocol?\n"
                                      "NOTE: This is required, in order to specify transport layer fields."):
                attrs = ['TCP', 'UDP', 'ICMPv6', 'SCTP', 'NONE']
                data = [[6, 17, 58, 132, 59]]
                print("Use one of the specified values below\n")
                print(tabulate(data, headers=attrs, tablefmt='fancy_grid'))

                while ip_proto is None:
                    try:
                        ip_proto = int(input('Protocol: '))
                        if ip_proto not in data[0]:
                            ip_proto = None
                            print("Protocol needs to be one of the specified values in the above table.")
                    except ValueError:
                        ip_proto = None
                        print("You need to enter a numerical value.\n")
                new_rule['ip_proto'] = ip_proto

        # TCP
        if ip_proto == 6:
            # TCP SOURCE PORT
            if self._get_binary_input("\nAdd source port number?"):
                tcp_src = None
                while tcp_src is None:
                    try:
                        tcp_src = int(input('Source port: '))
                        if tcp_src not in range(1, 65536):
                            tcp_src = None
                            print("Port needs to be in the range of valid port numbers (1-65535).")
                    except ValueError:
                        tcp_src = None
                        print("You need to enter a numerical value.\n")
                new_rule['tcp_src'] = tcp_src

            # TCP DESTINATION PORT
            if self._get_binary_input("\nAdd destination port number?"):
                tcp_dst = None
                while tcp_dst is None:
                    try:
                        tcp_dst = int(input('Destination port: '))
                        if tcp_dst not in range(1, 65536):
                            tcp_dst = None
                            print("Port needs to be in the range of valid port numbers (1-65535).")
                    except ValueError:
                        tcp_dst = None
                        print("You need to enter a numerical value.\n")
                new_rule['tcp_dst'] = tcp_dst

        # UDP
        elif ip_proto == 17:
            # UDP SOURCE PORT
            if self._get_binary_input("\nAdd source port number?"):
                udp_src = None
                while udp_src is None:
                    try:
                        udp_src = int(input('Source port: '))
                        if udp_src not in range(1, 65536):
                            udp_src = None
                            print("Port needs to be in the range of valid port numbers (1-65535).")
                    except ValueError:
                        udp_src = None
                        print("You need to enter a numerical value.\n")
                new_rule['udp_src'] = udp_src

            # UDP DESTINATION PORT
            if self._get_binary_input("\nAdd destination port number?"):
                udp_dst = None
                while udp_dst is None:
                    try:
                        udp_dst = int(input('Destination port: '))
                        if udp_dst not in range(1, 65536):
                            udp_dst = None
                            print("Port needs to be in the range of valid port numbers (1-65535).")
                    except ValueError:
                        udp_dst = None
                        print("You need to enter a numerical value.\n")
                new_rule['udp_dst'] = udp_dst

        # ICMPv6
        elif ip_proto == 58:
            # TYPE
            if self._get_binary_input("\nSpecify an ICMPv6 type?"):
                attrs = ['Type Description', 'Type Value']
                data = [
                    ['Destination Unreachable', 1],
                    ['Packet Too Big', 2],
                    ['Time Exceeded', 3],
                    ['Parameter Problem', 4],
                    ['Echo Request', 128],
                    ['Echo Reply', 129],
                    ['Router Solicitation', 133],
                    ['Router Advertisement', 134],
                    ['Neighbor Solicitation', 135],
                    ['Neighbor Advertisement', 136],
                    ['Redirect', 137]
                ]
                print("Use one of the specified values below, for ICMPv6 type\n")
                print(tabulate(data, headers=attrs, tablefmt='fancy_grid'))
                icmpv6_type = None
                while icmpv6_type is None:
                    try:
                        icmpv6_type = int(input('Type: '))
                        if icmpv6_type not in [item for sublist in data for item in sublist]:
                            icmpv6_type = None
                            print("Type needs to be one of the valid types shown in the above table.")
                    except ValueError:
                        icmpv6_type = None
                        print("You need to enter a numerical value.\n")
                new_rule['icmpv6_type'] = icmpv6_type

            # CODE
            if self._get_binary_input("\nSpecify an ICMPv6 code?"):
                icmpv6_code = None
                while icmpv6_code is None:
                    try:
                        icmpv6_code = int(input('Code: '))
                    except ValueError:
                        icmpv6_code = None
                        print("You need to enter a numerical value.\n")
                new_rule['icmpv6_code'] = icmpv6_code

        # Finally, return the new rule (as a dict)
        return new_rule

    # ============================= #
    # Sort CLI commands by category #
    # ============================= #
    categorize(do_connect, CMD_CATEGORY_CONNECTION)
    categorize(do_disconnect, CMD_CATEGORY_CONNECTION)
    categorize(do_query, CMD_CATEGORY_DATABASE)
    categorize(do_monitor, CMD_CATEGORY_MONITOR)
    categorize(do_rule, CMD_CATEGORY_RULES)
