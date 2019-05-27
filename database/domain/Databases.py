import sys
from datetime import datetime
from database import Connection
from pony.orm import PrimaryKey, Required, Optional, db_session, InternalError, Json, ObjectNotFound, select
from database.repository.Interfaces import LogRepository, RoutingRepository, FlowRepository, RulesetRepository

"""
This class represents the database entities (tables). The database (schemas) names can be 
set to anything, but if they are not the same as the default names, the custom names need to be
passed as parameters to the constructor (initialization method). If there are no tables in the 
schemas, then they will be automatically created by the ORM (object relational mapper). If there
are tables in the database, then the class methods and variables need to be overridden, ergo it 
is not recommended.
"""


ROUTING_DB_NAME = 'Routing'
LOGS_DB_NAME = 'Logs'
NETFLOWS_DB_NAME = 'NetworkFlows'
RULESETS_DB_NAME = 'Rulesets'


# Class that represents the Routing database
class Routing(RoutingRepository):

    def __init__(self, db_name=ROUTING_DB_NAME):
        super().__init__()
        try:
            self.db = Connection.Connection.connect_db_server_default(db_name)
        except InternalError:
            sys.exit("This schema does not exist.")

    @db_session
    def insert_address(self, address):
        """
        :param address: The address to insert to the table that contains the protected network's node addresses
        """
        Addresses(address=address)
        self.db.flush()

    @db_session
    def get_addresses(self):
        """
        :return: All the addresses in the 'addresses' table
        """
        return self.db.select("select * from Routing.addresses")

    @db_session
    def delete(self, address_id):
        """
        :param address_id: The PK of the address to delete
        :return: None if the given primary key (ID) does not exist in the table
        """
        try:
            Addresses[address_id].delete()
        except ObjectNotFound:
            return None

    @db_session
    def custom_query(self, query):
        """
        :param query: The user-generated query to run in db
        :return: The query results
        """
        return super().custom_query(query)

    @db_session
    def select_cols(self, table, selection):
        """
        :param table:  The table to query
        :param selection: The attributes to select
        :return: The query result
        """
        return super().select_cols(table, selection)

    @db_session
    def show_tables(self):
        """
        :return: The tables of this database
        """
        return super().show_tables()

    @db_session
    def describe_table(self, table_name):
        """
        :param table_name: The table to query
        :return: The table <description>
        """
        return super().describe_table(table_name)

    @db_session
    def get_table_attributes(self, table_name):
        """
        :param table_name: The table to query
        :return: The attributes of this table
        """
        return super().get_table_attributes(table_name)

    @db_session
    def clear_table(self, table_name="addresses"):
        """
        This method will call the TRUNCATE command, to clear the table and "re-seed" primary key auto incrementation
        :param table_name: The table to query
        """
        super().clear_table(table_name)


# Class that represents the Network Flows database
class NetFlows(FlowRepository):
    def __init__(self, db_name=NETFLOWS_DB_NAME):
        super().__init__()
        try:
            self.db = Connection.Connection.connect_db_server_default(db_name)
        except InternalError:
            sys.exit("This schema does not exist.")

    @db_session
    def get_flow_table(self):
        """
        :return: All records of the 'flows' table
        """
        return self.db.select("select * from NetworkFlows.flows")

    @db_session
    def delete_expired_rows(self):
        """
        This method will delete all records that have an "expiration_time" larger or equal to the current datetime.
        """
        now = datetime.now()
        expired_rows = select(f.id for f in Flows if f.expiration_time <= now)  # select expired records
        expired_rows = expired_rows.fetch()

        for row_id in expired_rows:
            Flows[row_id].delete()

    @db_session
    def insert(self, **kwargs):
        """
        This method will firstly delete expired records, and then it will add a new flow record
        :param kwargs: Dictionary containing all the values to be inserted
        """
        self.delete_expired_rows()
        in_port = str(kwargs.get('in_port'))
        eth_dst = str(kwargs.get('eth_dst'))
        eth_src = str(kwargs.get('eth_src'))
        eth_type = str(kwargs.get('eth_type'))
        ipv6_src = str(kwargs.get('ipv6_src'))
        ipv6_dst = str(kwargs.get('ipv6_dst'))
        layer4_protocol = str(kwargs.get('l4_protocol'))
        tcp_src = str(kwargs.get('tcp_src')) if kwargs.get('tcp_src')is not None else "Any"
        tcp_dst = str(kwargs.get('tcp_dst')) if kwargs.get('tcp_dst')is not None else "Any"
        udp_src = str(kwargs.get('udp_src')) if kwargs.get('udp_src')is not None else "Any"
        udp_dst = str(kwargs.get('udp_dst')) if kwargs.get('udp_dst')is not None else "Any"
        icmpv6_type = str(kwargs.get('icmpv6_type'))
        icmpv6_code = str(kwargs.get('icmpv6_code'))
        action = str(kwargs.get('action'))
        expiration_time = kwargs.get('expiration_time')

        Flows(
            in_port=in_port, eth_dst=eth_dst, eth_src=eth_src, eth_type=eth_type, ipv6_src=ipv6_src, ipv6_dst=ipv6_dst,
            layer4_protocol=layer4_protocol, tcp_src=tcp_src, tcp_dst=tcp_dst, udp_src=udp_src, udp_dst=udp_dst,
            icmpv6_type=icmpv6_type, icmpv6_code=icmpv6_code, action=action, expiration_time=expiration_time
        )

    @db_session
    def show_tables(self):
        """
        :return: The tables of this database
        """
        return super().show_tables()

    @db_session
    def describe_table(self, table_name):
        """
        :param table_name: The table to query
        :return: The table <description>
        """
        return super().describe_table(table_name)

    @db_session
    def get_table_attributes(self, table_name):
        """
        :param table_name: The table to query
        :return: The attributes of this table
        """
        return super().get_table_attributes(table_name)

    @db_session
    def custom_query(self, query):
        """
        :param query: The user-generated query to run in db
        :return: The query results
        """
        self.delete_expired_rows()
        return super().custom_query(query)

    @db_session
    def select_cols(self, table, selection):
        """
        :param table:  The table to query
        :param selection: The attributes to select
        :return: The query result, after deleting the expired rows first
        """
        self.delete_expired_rows()
        return super().select_cols(table, selection)

    @db_session
    def clear_table(self, table_name="flows"):
        """
        This method will call the TRUNCATE command, to clear the table and "re-seed" primary key auto incrementation
        :param table_name: The table to query
        """
        super().clear_table(table_name)


class Rulesets(RulesetRepository):
    # These global variables are used for consistency. "New" is for newly inserted rule objects and
    # "current" is for rules that have not been updated at the time that they are queried.
    new_version = "NEW"
    up_to_date = "CURRENT"

    def __init__(self, db_name=RULESETS_DB_NAME):
        super().__init__()
        try:
            self.db = Connection.Connection.connect_db_server_default(db_name)
        except InternalError:
            sys.exit("This schema does not exist.")

    @db_session
    def update_ruleset(self, ruleset, ruleset_id=1):
        """
        This function will update the current json-type ruleset, with the new one
        :param ruleset: The new (dictionary) object to store
        :param ruleset_id: The pk of the primary ruleset
        """
        r = Rules[ruleset_id]
        r.ruleset.update(ruleset)
        r.version = Rulesets.new_version
        self.db.commit()

    @db_session
    def new_ruleset_exists(self):
        """
        :return: True, if the master ruleset is marked as new
        """
        ruleset = Rules[1]
        return ruleset.version == Rulesets.new_version

    @db_session
    def get_ruleset(self, ruleset_id=1) -> dict:
        """
        :param ruleset_id:
        :return:
        """
        ruleset = Rules[ruleset_id]
        return dict(ruleset.ruleset)

    @db_session
    def mark_ruleset(self, ruleset_id=1, marking=new_version):
        """
        This method will mark a ruleset as "NEW" or "UP-TO-DATE".
        :param ruleset_id: The id of the ruleset to mark
        :param marking: what should the "version" field be changed to
        """
        ruleset = Rules[ruleset_id]
        ruleset.version = marking

    @db_session
    def insert_ruleset(self, ruleset_dict):
        """
        Insert a new ruleset in database
        :param ruleset_dict: the ruleset to insert
        """
        Rules(ruleset=ruleset_dict, version=Rulesets.new_version)

    @db_session
    def show_tables(self):
        """
        :return: The tables of this database
        """
        return super().show_tables()

    @db_session
    def describe_table(self, table_name):
        """
        :param table_name: The table to describe
        :return: The table <description>
        """
        return super().describe_table(table_name)

    @db_session
    def get_table_attributes(self, table_name):
        """
        :param table_name: The table to get the attributes of
        :return: The table's attributes
        """
        return super().get_table_attributes(table_name)

    @db_session
    def custom_query(self, query):
        """
        :param query: The user-generated query to run
        :return: The result of the custom query
        """
        return super().custom_query(query)

    @db_session
    def select_cols(self, table, selection):
        """
        :param table:  The table to query
        :param selection: The attributes to select
        :return: The query result, after deleting the expired rows first
        """
        return super().select_cols(table, selection)

    @db_session
    def clear_table(self, table_name="rules"):
        """
        This method will call the TRUNCATE command, to clear the table and "re-seed" primary key auto incrementation
        :param table_name: The table to query
        """
        super().clear_table(table_name)


# Class that represents the Routing database
class Logs(LogRepository):

    def __init__(self, db_name=LOGS_DB_NAME):
        super().__init__()
        try:
            self.db = Connection.Connection.connect_db_server_default(db_name)
        except InternalError:
            sys.exit("This schema does not exist.")

    @db_session
    def add_record(self, **kwargs):
        """
        This method will insert a new record in 'log_records'
        :param kwargs: The dictionary containing the values for a record
        """
        date_time = datetime.now()
        src_mac = kwargs['src_mac']
        dst_mac = kwargs['dst_mac']
        src_ip = kwargs['src_ip']
        dst_ip = kwargs['dst_ip']
        protocol = kwargs['protocol']
        trust_level = kwargs['trust_level']
        action = kwargs['action']
        justification = kwargs['justification']

        LogRecords(date_time=date_time, src_mac=src_mac, dst_mac=dst_mac, src_ip=src_ip,
                   dst_ip=dst_ip, protocol=protocol, trust_level=trust_level,
                   action=action, justification=justification)

    @db_session
    def get_log_by_time(self, dtime, logid=None):
        """
        :param dtime: The datetime (now()), as a filter for the records. Return only records that are past this time.
        :param logid: If this is set, ignore records with a smaller value than this
        :return: The set of records that were inserted after the dtime and have larger PK than logid.
        """
        dtime = str(dtime)
        logid = str(logid)

        if logid == 'None':
            return self.db.select("SELECT * FROM log_records WHERE date_time >= $dtime")
        else:
            return self.db.select("SELECT * FROM log_records WHERE date_time >= $dtime AND id > $logid")

    @db_session
    def get_all_logs(self):
        """
        :return: All the records in log_records
        """
        return self.db.select("SELECT * FROM log_records")

    @db_session
    def custom_query(self, query):
        """
        :param query: The user-generated query to run
        :return: The result of the custom query
        """
        return super().custom_query(query)

    @db_session
    def clear_table(self, table_name="log_records"):
        """
        This method will call the TRUNCATE command, to clear the table and "re-seed" primary key auto incrementation
        :param table_name: The table to query
        """
        super().clear_table(table_name)

    @db_session
    def select_cols(self, table, selection):
        """
        :param table:  The table to query
        :param selection: The attributes to select
        :return: The query result, after deleting the expired rows first
        """
        return super().select_cols(table, selection)

    @db_session
    def show_tables(self):
        """
        :return: The tables of this database
        """
        return super().show_tables()

    @db_session
    def describe_table(self, table_name):
        """
        :param table_name: The table to describe
        :return: The table <description>
        """
        return super().describe_table(table_name)

    @db_session
    def get_table_attributes(self, table_name):
        """
        :param table_name: The table to get the attributes of
        :return: The table's attributes
        """
        return super().get_table_attributes(table_name)


# Initialize the database Schemas. These are considered to be empty for when the system is first run.
routing = Routing()
logs = Logs()
flows = NetFlows()
rules = Rulesets()

# ============================================================== #
# The following classes declared here, represent schema tables.  #
# That is why they inherit from the just-initialized             #
# schemas' database objects (-- see AbstractRepository.db --).   #
# ============================================================== #


# =================ROUTING SCHEMA================= #
class Addresses(routing.get_database().Entity):
    _table_ = "addresses"
    id = PrimaryKey(int, auto=True)
    address = Required(str)


# ==================LOGS SCHEMA=================== #
class LogRecords(logs.get_database().Entity):
    _table_ = "log_records"
    id = PrimaryKey(int, auto=True)
    date_time = Required(datetime, 6)
    src_mac = Required(str, column="mac_src_address")
    dst_mac = Required(str, column="mac_dst_address")
    src_ip = Required(str, column="ip_src_address")
    dst_ip = Required(str, column="ip_dst_address")
    protocol = Required(str, column="protocol")
    trust_level = Required(str, column="trust_level")
    action = Required(str, column="action")
    justification = Required(str, column="justification")


# ==============NETWORK FLOWS SCHEMA============== #
class Flows(flows.get_database().Entity):
    _table_ = "flows"
    id = PrimaryKey(int, auto=True)
    in_port = Optional(str, nullable=True)
    eth_dst = Optional(str, nullable=True)
    eth_src = Optional(str, nullable=True)
    eth_type = Optional(str, nullable=True)
    ipv6_src = Optional(str, nullable=True)
    ipv6_dst = Optional(str, nullable=True)
    layer4_protocol = Optional(str, nullable=True)
    tcp_src = Optional(str, nullable=True)
    tcp_dst = Optional(str, nullable=True)
    udp_src = Optional(str, nullable=True)
    udp_dst = Optional(str, nullable=True)
    icmpv6_type = Optional(str, nullable=True)
    icmpv6_code = Optional(str, nullable=True)
    action = Optional(str, nullable=True)
    expiration_time = Optional(datetime, 6)


# ==============RULESETS SCHEMA============== #
class Rules(rules.get_database().Entity):
    _table_ = "rules"
    id = PrimaryKey(int, auto=True)
    ruleset = Required(Json)
    version = Required(str)  # can be either 'new', or 'current'


# Check if class representations are consistent with database schema and if tables don't exist, create them.
routing.get_database().generate_mapping(check_tables=True, create_tables=True)
logs.get_database().generate_mapping(check_tables=True, create_tables=True)
flows.get_database().generate_mapping(check_tables=True, create_tables=True)
rules.get_database().generate_mapping(check_tables=True, create_tables=True)
