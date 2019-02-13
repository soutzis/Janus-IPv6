from abc import ABCMeta, abstractmethod


class AbstractRepository(metaclass=ABCMeta):

    def __init__(self):
        self.db = NotImplemented

    def get_database(self):
        return self.db

    # Function show_tables will return a list with all the table names in schema
    @abstractmethod
    def show_tables(self):
        cursor = self.db.execute("SHOW TABLES")
        result = cursor.fetchall()
        tables = []
        for table in result:
            tables.append(table[0])
        return tables

    @abstractmethod
    def describe_table(self, table_name):
        query = "DESCRIBE "+table_name
        cursor = self.db.execute(query)
        return cursor.fetchall()

    @abstractmethod
    def get_table_attributes(self, table_name):
        query = "DESCRIBE " + table_name
        cursor = self.db.execute(query)
        result = cursor.fetchall()
        attributes = []
        for attr in result:
            attributes.append(attr[0])
        return attributes

    @abstractmethod
    def custom_query(self, query):
        cursor = self.db.execute(query)
        return cursor.fetchall()

    @abstractmethod
    def select_cols(self, table, selection):
        attributes = ""
        for attr in selection:
            x = "," + attr
            attributes += x
        attributes = attributes[1:]
        query = "SELECT " + attributes + " FROM " + table

        return self.db.select(query)

    # @abstractmethod
    # def select_cols_with_condition(self, table, selection, **conditions):
    #     attributes = ""
    #     for attr in selection:
    #         x = "," + attr
    #         attributes += x
    #     attributes = attributes[1:]
    #     query = "SELECT " + attributes + " FROM " + table


class LogRepository(AbstractRepository):

    @abstractmethod
    def get_all_logs(self):
        pass

    @abstractmethod
    def get_logs_by(self, *,
                    date,
                    time,
                    mac_src,
                    mac_dst,
                    ip_src,
                    ip_dst,
                    action,
                    justification,
                    trust_level):
        pass

    @abstractmethod
    def clear_logs(self):
        pass


class RulesetRepository(AbstractRepository):

    @abstractmethod
    def get_ruleset(self, name):
        pass

    def update_ruleset(self, name, ruleset):
        pass


class FlowRepository(AbstractRepository):

    @abstractmethod
    def insert(self, entry):
        pass

    @abstractmethod
    def update(self, current_entry, new_entry):
        pass

    @abstractmethod
    def delete(self, entry):
        pass

    @abstractmethod
    def get_flow_table(self):
        pass

    @abstractmethod
    def get_flow(self, entry):
        pass


class RoutingRepository(AbstractRepository):

    @abstractmethod
    def get_routing_table(self):
        pass

    @abstractmethod
    def prefix_exists(self, prefix):
        pass

    @abstractmethod
    def get_addresses_by_prefix(self, prefix):
        pass

    @abstractmethod
    def insert_prefix(self, new_id, new_prefix):
        pass

    @abstractmethod
    def update(self, current_entry, new_entry):
        pass

    @abstractmethod
    def delete(self, entry):
        pass
