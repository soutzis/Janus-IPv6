from pony import orm

'''
PONY ORM Requires that the relationship between tables
is always bi-directional. Parent/referenced tables, need to
have a redundant attribute that is a foreign key to the child table.
This can cause confusion, but this will be disambiguated in the 
documentation of each class that represents a database.
'''


class Connection:
    # This will initialize a connection to the default database
    @staticmethod
    def connect_db_server_default(username, password, db_name='', host_addr='127.0.0.1'):
        db = orm.Database()
        db.bind(provider='mysql', user=username, password=password, host=host_addr, database=db_name)

        return db

    # This will allow connection to a database/schema
    @staticmethod
    def connect_db_server(provider='', username='', password='', host_addr='', db_name=''):
        db = orm.Database()
        db.bind(provider=provider, user=username, password=password, host=host_addr, database=db_name)

        return db
