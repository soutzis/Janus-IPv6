import sys
from datetime import datetime
from database import Connection
from pony.orm import PrimaryKey, Required, Set, Optional, db_session, InternalError
from database.repository.Interfaces import LogRepository, RoutingRepository

"""
This class represents the database entities (tables). The database (schemas) names can be 
set to anything, but if they are not the same as the default names, the custom names need to be
passed as parameters to the constructor (initialization method). If there are no tables in the 
schemas, then they will be automatically created by the ORM (object relational mapper). If there
are tables in the database, then the class methods and variables need to be overridden, ergo it 
is not recommended.
"""


# Class that represents the Routing database
class Routing(RoutingRepository):
    def __init__(self, db_name='Routing'):
        super().__init__()
        try:
            self.db = Connection.Connection.connect_db_server_default(db_name)
        except InternalError:
            sys.exit("This database name does not exist.")

        # self.db.generate_mapping(check_tables=True, create_tables=True)

    @db_session
    def get_routing_table(self):
        query = "SELECT prefixes.prefix, addresses.address FROM prefixes, addresses WHERE prefix_id = prefixes.id"
        return self.db.select(query)

    @db_session
    def prefix_exists(self, prefix):
        pref = Prefixes.get(prefix=prefix)
        if pref is not None:
            return True
        else:
            return False

    @db_session
    def get_addresses_by_prefix(self, prefix):
        query = "SELECT addresses.address FROM addresses LEFT JOIN prefixes ON " \
                "prefix_id = prefixes.id WHERE prefix = \""+prefix+"\""
        return self.db.select(query)

    @db_session
    def insert_prefix(self, new_id, new_prefix):
        Prefixes(id=new_id, prefix=new_prefix)

    @db_session
    def insert_address(self, new_id, new_address, prefix_id):
        Addresses(id=new_id, address=new_address, prefix_id=prefix_id)

    @db_session
    def update(self, current_entry, new_entry):
        pass

    @db_session
    def delete(self, condition):
        pass

    @db_session
    def custom_query(self, query):
        return super().custom_query(query)

    @db_session
    def select_cols(self, table, selection):
        return super().select_cols(table, selection)

    @db_session
    def show_tables(self):
        return super().show_tables()

    @db_session
    def describe_table(self, table_name):
        return super().describe_table(table_name)

    @db_session
    def get_table_attributes(self, table_name):
        return super().get_table_attributes(table_name)


# Class that represents the Routing database
class Logs(LogRepository):
    def __init__(self, db_name='Logs'):
        super().__init__()
        try:
            self.db = Connection.Connection.connect_db_server_default(db_name)
        except InternalError:
            sys.exit("This database name does not exist.")

        # self.db.generate_mapping(check_tables=True, create_tables=True)

    # Returns a list with all the  trust levels available
    @db_session
    def get_trust_levels(self):
        return self.db.select("SELECT trust_level FROM trust_levels")

    @db_session
    def get_all_logs(self):
        return self.db.select("SELECT * FROM log_records")

    @db_session
    def custom_query(self, query):
        return super().custom_query(query)

    @db_session
    def get_logs_by(self, *, date=None, time=None, mac_src=None, mac_dst=None, ip_src=None,
                    ip_dst=None, action=None, justification=None, trust_level=None):
        pass

    @db_session
    def clear_logs(self):
        pass

    @db_session
    def select_cols(self, table, selection):
        return super().select_cols(table, selection)

    @db_session
    def show_tables(self):
        return super().show_tables()

    @db_session
    def describe_table(self, table_name):
        return super().describe_table(table_name)

    @db_session
    def get_table_attributes(self, table_name):
        return super().get_table_attributes(table_name)


# Initialize entities, which are database tables, represented as Python objects
routing = Routing()
logs = Logs()


# Table addresses is the child of prefixes. It references
# 'prefixes' table via foreign-key 'prefix_id'
class Addresses(routing.get_database().Entity):
    _table_ = "addresses"
    id = PrimaryKey(int, auto=False)
    address = Required(str)
    prefix_id = Required(lambda: Prefixes)


class Prefixes(routing.get_database().Entity):
    _table_ = "prefixes"
    id = PrimaryKey(int, auto=False)
    prefix = Required(str)
    address = Optional(Addresses, cascade_delete=True)


class TrustLevels(logs.get_database().Entity):
    _table_ = "trust_levels"
    id = PrimaryKey(int, auto=True)
    trust_level = Required(str)
    log_record_id = Optional(lambda: LogRecords)


class Actions(logs.get_database().Entity):
    id = PrimaryKey(int, auto=True)
    action = Required(str)
    log_record_id = Optional(lambda: LogRecords)


class Justifications(logs.get_database().Entity):
    id = PrimaryKey(int, auto=True)
    justification = Required(str)
    log_record_id = Optional(lambda: LogRecords)


class LogRecords(logs.get_database().Entity):
    _table_ = "log_records"
    id = PrimaryKey(int, auto=True)
    date_time = Required(datetime, 6)
    src_mac = Required(str, column="mac_src_address")
    dst_mac = Required(str, column="mac_dst_address")
    src_ip = Required(str, column="ip_src_address")
    dst_ip = Required(str, column="ip_dst_address")
    trust_level = Required(TrustLevels, column="trust_level_id")
    action = Required(Actions, column="action_id")
    justification = Required(Justifications, column="justification_id")


# check if class representations are consistent with database schema and if tables don't exist, create them.
routing.get_database().generate_mapping(check_tables=True, create_tables=True)
logs.get_database().generate_mapping(check_tables=True, create_tables=True)
