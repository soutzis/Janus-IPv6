import json
from socket import socket

import rpyc
import logging

from rpyc.utils.server import ThreadedServer
from database.domain.Databases import routing, logs, flows, rules


_ADMIN_FILE = '/home/soutzis/PycharmProjects/Janus_IPv6/admin.json'


class JanusIPv6Service(rpyc.Service):
    def __init__(self):
        self.service_name = "\'JanusIPv6 Repository\'"
        self.db_schemas = {
            "logs": logs,
            "routing": routing,
            "flows": flows,
            "ruleset": rules
        }
        # Client socket details
        self.client_ip = None
        self.client_port = None

        # Read the passwords stored for administrator access
        self.pswds_dict = self._read_passwords()

    def on_connect(self, conn):
        """
        This is called whenever a connection is initiated to the server by a client. It will
        get the IP address and client port number from the socket stream (the comm. channel used)
        :param conn: It is the connection object that characterizes the client connected to this server thread.
        """
        # socket.getpeername() is a 4-tuple
        self.client_ip, self.client_port, _, _ = socket.getpeername(conn._channel.stream.sock)
        print("\nConnection established with", self.client_ip)

    def on_disconnect(self, conn):
        """
        This is called whenever a connected client disconnect from the service. It clears ip and port number.
        :param conn: It is the connection object that characterizes the client connected to this server thread.
        """
        conn.close()
        print("Connection with {} was terminated.\n".format(self.client_ip))
        self.client_ip = None
        self.client_port = None

    # noinspection PyBroadException
    @staticmethod
    def _read_passwords():
        """
        This method will read the passwords of administrators from a json file and return
        a python dictionary equivalent
        :return: A dictionary containing information about administrators (including passwords)
        """
        pswds_dict = None
        try:
            with open(_ADMIN_FILE, "r") as f:
                pswds_dict = json.load(f)  # Get passwords from .json file as a dictionary
        except Exception:
            print("Could not load the admin passwords")

        return pswds_dict

    def exposed_authenticate_admin(self, password):
        """
        This function will read the admin passwords from a .json file and compare the user input with them
        :param password: The password that the client has provided
        :return: True if the user entered the right password, or false if the user entered the wrong password.
        """
        for pswd in self.pswds_dict['admins']:
            if password == pswd['password']:
                print("Client with address \"{}\" authenticated as \"administrator\"".format(self.client_ip))
                return True

        logging.warning("Wrong password entered from client at address \"{}\".".format(self.client_ip))
        return False

    def exposed_get_service_name(self):
        """
        :return: The name of this service. (JanusIPv6 Repository)
        """
        return self.service_name

    def exposed_show_tables(self, db_name):
        """
        :param db_name: The name of the schema to query
        :return: A list containing all the tables of specified schema (db_name)
        """
        db = self.db_schemas[db_name]
        result = db.show_tables()
        return result

    def exposed_describe_table(self, db_name, table_name):
        """
        :param db_name: The name of the database to query
        :param table_name: The name of the table to describe
        :return: Use to obtain information about table structure or query execution plans
        """
        db = self.db_schemas[db_name]
        result = db.describe_table(table_name)
        return result

    def exposed_table_attributes(self, db_name, table_name):
        """
        :param db_name: The name of the database to query
        :param table_name: The name of the table to view the attributes of
        :return: The attributes (their name) of the specified table.
        """
        db = self.db_schemas[db_name]
        result = db.get_table_attributes(table_name)
        return result

    def exposed_custom_query(self, db_name, query):
        """
        This method will execute a custom query written by the Client user.
        :param db_name: The name of the database to query
        :param query: The MySQL query (Must be valid MySQL syntax!)
        :return: The result of the custom query
        """
        db = self.db_schemas[db_name]
        result = db.custom_query(query)
        return result

    def exposed_select(self, db_name, table_name, attributes):
        """
        This method lets the user select one or multiple attributes from a table and view the rows
        :param db_name: The database to query
        :param table_name: The name of the table
        :param attributes: The name of the attributes
        :return: The result, containing the records that were queried by the user
        """
        db = self.db_schemas[db_name]
        result = db.select_cols(table_name, attributes)
        return result

    def exposed_monitor(self, datetime, previous_id):
        """
        This method will start an active monitoring phase, where the server will return
        a log entry or alert from the controller, as soon as it is generated and inserted to the
        database. It will return None, if there is no item in the Alerts Queue
        """
        # Get the object that is initialised as the Logs database and
        # set the 'Monitoring' flag to true. Then start endless bidirectional
        # calls to the function (in Client) that calls !!this!! function.
        #
        # This way, unless the Client exits the monitoring phase, this will keep returning
        # alerts to the Client.
        db = self.db_schemas['logs']
        result = db.get_log_by_time(datetime, previous_id)

        if not result:
            return None
        else:
            return result

    def exposed_update_ruleset(self, ruleset):
        """
        :param ruleset: The ruleset to use, to update the existing one.
        """
        self.db_schemas['ruleset'].update_ruleset(ruleset)

    def exposed_get_ruleset(self, ruleset_id=1):
        """
        :param ruleset_id: The id of the ruleset to retrieve
        :return: The ruleset
        """
        return self.db_schemas['ruleset'].get_ruleset(ruleset_id)


if __name__ == "__main__":
    # Initialize the Server, running JanusIPv6Service only.
    server = ThreadedServer(
        JanusIPv6Service, hostname="::1", ipv6=True, port=12160, protocol_config={"allow_all_attrs": True}
    )
    print("Started listening on [{}]:{}".format(server.host, server.port))
    server.start()
