from pony import orm


# This will initialize a connection to the default database
def connect_db_server_default(db_name='', host_addr='127.0.0.1'):
    db = orm.Database()
    db.bind(provider='mysql', user='root', password='1216024', host=host_addr, database=db_name)

    return db


# This will allow connection to a database/schema
def connect_db_server(provider='', username='', password='', host_addr='', db_name=''):
    db = orm.Database()
    db.bind(provider=provider, user=username, password=password, host=host_addr, database=db_name)

    return db


# db_routing = connect_db_server_default('Routing')
