#!/usr/bin/python3.6
import socket
from database.domain import Databases

# address that the server listens to. (Loopback interface for local execution)
HOST_ADDRESS = '127.0.0.1'
# port address for communication
PORT = 12160


# socket module supports the with context manager type (no need to close() socket)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # bind to address and port specified in this script
    s.bind((HOST_ADDRESS, PORT))
    # listen for connections and block & accept them [backlog = 1 (queued non-accepted connections limit)]
    s.listen(1)
    # received socket object for communication
    conn, addr = (None, None)
    try:
        conn, addr = s.accept()
    except KeyboardInterrupt:
        print("Server terminated by admin.")
        exit(0)

    # with statement, so that connection closes automatically when exiting statement
    with conn:
        print('Connected by', addr)
        while True:
            # receive bytes from client
            data = conn.recv(4096)
            # if connection was closed by the client, block and wait for connection. (keep looping)
            if not data:
                try:
                    conn, addr = s.accept()
                except KeyboardInterrupt:
                    print("Server terminated by admin.")
                    exit(0)
            # send everything back to client
            conn.sendall(data)

# log_db = Databases.Logs()
# routing_db = Databases.Routing()
