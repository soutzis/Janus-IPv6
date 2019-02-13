import rpyc
from rpyc.utils.server import ThreadedServer
from database.domain.Databases import logs, routing, Prefixes


class JanusIPv6Service(rpyc.Service):
    def __init__(self):
        self.service_name = "\'JanusIPv6 Repository\'"
        self.db_schemas = {
            "logs": logs,
            "routing": routing,
            "flows": None,
            "ruleset": None
        }

    def on_connect(self, conn):
        print("Connection established", conn)

    def exposed_authenticate(self, encrypted_msg):
        pass

    def exposed_get_service_name(self):
        return self.service_name

    def exposed_show_tables(self, db_name):
        db = self.db_schemas[db_name]
        result = db.show_tables()
        return result

    def exposed_describe_table(self, db_name, table_name):
        db = self.db_schemas[db_name]
        result = db.describe_table(table_name)
        return result

    def exposed_table_attributes(self, db_name, table_name):
        db = self.db_schemas[db_name]
        result = db.get_table_attributes(table_name)
        return result

    def exposed_custom_query(self, db_name, query):
        db = self.db_schemas[db_name]
        result = db.custom_query(query)
        return result

    def exposed_select(self, db_name, table_name, attributes):
        db = self.db_schemas[db_name]
        result = db.select_cols(table_name, attributes)
        return result

    def exposed_get_routing_table(self):
        db = self.db_schemas['routing']
        result = db.get_routing_table()
        return result


if __name__ == "__main__":
    # 'hostname' argument for ThreadedServer constructor, gives an error when using "localhost" & ipv6.
    server = ThreadedServer(JanusIPv6Service, hostname="::1", ipv6=True, port=12160)
    print("Started listening on [{}]:{}".format(server.host, server.port))
    server.start()
