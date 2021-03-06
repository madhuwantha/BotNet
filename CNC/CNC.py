import socket
from threading import Thread
import time

from Env import Env

env = Env()

bot_ip = env.get(key="botIp")
list_of_clients = []
threads = []


def botThread(conn, addr):
    print("Starting in bot", addr)
    conn.send(bytes('START ' + "" + '\r\n', "UTF-8"))
    while True:
        try:
            cmd = conn.recv(2048).decode("UTF-8")
            print(cmd)
            conn.send(bytes('START ' + "" + '\r\n', "UTF-8"))
            broadcast(cmd, conn)
        except:
            continue


def iotThread(conn, addr):
    # print("Communicating with ", addr)
    errors = 0
    start = time.time()
    # sends a message to the client whose user object is conn
    conn.send(bytes('START ' + "" + '\r\n', "UTF-8"))

    while True:
        try:
            dif = abs(time.time() - start)
            if dif > 5:
                try:
                    conn.send(bytes('PING ' + '\r\n', "UTF-8"))
                    message = conn.recv(2048)
                    # print(message)
                except:
                    errors = errors + 1
                    if errors > 5:
                        remove(conn)

                start = time.time()
        except:
            continue


def broadcast(message, connection):
    """
    Using the below function, we broadcast the message to all
    clients who's object is not the same as the one sending
    the message
    :param message:
    :param connection:
    :return:
    """
    print("Starting broadcasting...")
    for client in list_of_clients:
        print("broadcasting to ", client)
        if client != connection:
            try:
                client.send(bytes(message + "" + '\r\n', "UTF-8"))
                print("broadcasted ", client)
            except:
                print("could not broadcasting to ", client)
                client.close()
                # if the link is broken, we remove the client
                remove(client)


def remove(connection):
    """
    The following function simply removes the object
    from the list that was created at the beginning of
    the program
    :param connection:
    :return:
    """
    if connection in list_of_clients:
        list_of_clients.remove(connection)


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

IP_address = str(env.get(key="serverIp"))
Port = int(env.get(key="serverPort"))
server.bind((IP_address, Port))

""" 
listens for 100 active connections. This number can be 
increased as per convenience. 
"""
server.listen(100)
conn = None
try:
    while True:
        print("Waiting for client to connect...")
        conn, addr = server.accept()
        list_of_clients.append(conn)

        # prints the address of the user that just connected
        print(addr[0] + " connected")

        handler = None
        if addr[0] == bot_ip[0] or addr[0] == bot_ip[1]:
            handler = botThread
        else:
            handler = iotThread

        t = Thread(target=handler, args=(conn, addr))
        t.start()
        threads.append(t)
except KeyboardInterrupt:
    print("Press Ctrl-C to terminate while statement")
    conn.close()
    server.close()
