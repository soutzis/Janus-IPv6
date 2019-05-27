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
            tables.append([table[0]])
        return tables

    @abstractmethod
    def describe_table(self, table_name):
        query = "DESCRIBE " + table_name
        cursor = self.db.execute(query)
        return cursor.fetchall()

    @abstractmethod
    def get_table_attributes(self, table_name):
        # query = "DESCRIBE " + table_name
        # cursor = self.db.execute(query)
        result = self.describe_table(table_name)
        attributes = []
        for attr in result:
            attributes.append([attr[0]])
        return attributes

    @abstractmethod
    def custom_query(self, query):
        data = []
        attrs = []
        cursor = self.db.execute(query)

        # Get the attribute name of each column of this query result, and add it to a list.
        for attribute_description in cursor.description:
            attrs.append(attribute_description[0])

        data.append(attrs)

        # Add each record to the list containing all of the results from the query
        for record in cursor.fetchall():
            data.append(list(record))

        return data

    @abstractmethod
    def select_cols(self, table, selection):
        attributes = ""
        for attr in selection:
            x = "," + attr
            attributes += x
        attributes = attributes[1:]
        query = "SELECT " + attributes + " FROM " + table

        return self.db.select(query)

    @abstractmethod
    def clear_table(self, table_name):
        self.db.execute("TRUNCATE TABLE "+table_name+";")


class LogRepository(AbstractRepository):

    @abstractmethod
    def get_all_logs(self):
        pass


class RulesetRepository(AbstractRepository):

    @abstractmethod
    def get_ruleset(self, ruleset_id):
        pass

    @abstractmethod
    def update_ruleset(self, ruleset_id, new_ruleset):
        pass


class FlowRepository(AbstractRepository):

    @abstractmethod
    def insert(self, entry):
        pass

    @abstractmethod
    def delete_expired_rows(self):
        pass

    @abstractmethod
    def get_flow_table(self):
        pass


class RoutingRepository(AbstractRepository):

    @abstractmethod
    def get_addresses(self):
        pass

    def insert(self):
        pass

    def delete(self, address_id):
        pass
