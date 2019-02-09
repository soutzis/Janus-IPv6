import sys
from datetime import datetime
from database import Connection
from pony.orm import PrimaryKey, Required, Set, Optional, db_session, InternalError
from database.repository.Interfaces import LogRepository


# Class that represents the Routing database
class Routing:
    def __init__(self, db_name='Routing'):
        try:
            self.db = Connection.Connection.connect_db_server_default(db_name)
        except InternalError:
            sys.exit("This database name does not exist.")

        # Table addresses is the child of prefixes. It references
        # 'prefixes' table via foreign-key 'prefix_id'
        class Addresses(self.db.Entity):
            _table_ = "addresses"
            id = PrimaryKey(int, auto=False)
            address = Required(str)
            prefix_id = Required(lambda: Prefixes)

        class Prefixes(self.db.Entity):
            _table_ = "prefixes"
            id = PrimaryKey(int, auto=False)
            prefix = Required(str)
            address = Optional(Addresses)

        self.db.generate_mapping(check_tables=True, create_tables=True)

    @db_session
    def select_cols(self, table, selection='*'):
        query = "SELECT " + selection + " FROM " + table
        return self.db.select(query)

    @db_session
    def disconnect(self):
        self.db.disconnect()


# Class that represents the Routing database
class Logs(LogRepository):
    def __init__(self, db_name='Logs'):
        try:
            self.db = Connection.Connection.connect_db_server_default(db_name)
        except InternalError:
            sys.exit("This database name does not exist.")

        class TrustLevels(self.db.Entity):
            _table_ = "trust_levels"
            id = PrimaryKey(int, auto=True)
            trust_level = Required(str)
            log_record_id = Optional(lambda: LogRecords)

        class Actions(self.db.Entity):
            id = PrimaryKey(int, auto=True)
            action = Required(str)
            log_record_id = Optional(lambda: LogRecords)

        class Justifications(self.db.Entity):
            id = PrimaryKey(int, auto=True)
            justification = Required(str)
            log_record_id = Optional(lambda: LogRecords)

        class LogRecords(self.db.Entity):
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

            # i dont know what the creator was thinking
            @db_session
            def get_first_log(self):
                return LogRecords[0]

        self.db.generate_mapping(check_tables=True, create_tables=True)

    # Returns a list with all the  trust levels available
    @db_session
    def get_trust_levels(self):
        return self.db.select("SELECT trust_level FROM trust_levels")

    @db_session
    def get_all_logs(self):
        return self.db.select("SELECT * FROM log_records")

    # TODO IMPLEMENT ABSTRACT METHODS
    @db_session
    def get_logs_by_date(self, date):
        pass

    @db_session
    def clear_logs(self):
        pass

    @db_session
    def truncate_table(self):
        pass

    @db_session
    def disconnect(self):
        self.db.disconnect()


# x = Routing('Routing')
first_log = Logs().get_all_logs()[0]
print(first_log)
# data = x.get_trust_levels()
# print(x.select_cols("prefixes"))
