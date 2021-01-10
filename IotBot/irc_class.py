import socket
import time


class IRC:
    irc = socket.socket()

    def __init__(self):
        # Define the socket
        self.irc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def send(self, channel, msg):
        # Transfer data
        self.irc.send(bytes("PRIVMSG " + channel + " " + msg + "\n", "UTF-8"))

    def connect(self, server, port):
        # Connect to the server
        print("Connecting to: " + server)
        self.irc.connect((server, port))
        print("Connected")

    def get_response(self):
        time.sleep(1)
        # Get the response
        resp = self.irc.recv(2040).decode("UTF-8")

        if resp.find('CMD') != -1:
            # TODO :  executing the command
            pass

        if resp.find('PING') != -1:
            # print(resp)
            self.irc.send(bytes('PONG ' + "" + '\r\n', "UTF-8"))

        return resp

    def close(self):
        self.irc.close()
