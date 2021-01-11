from irc_class import IRC

server = "192.168.8.101"
port = 7000
irc = IRC()

try:
    irc.connect(server, port)
except:
    print("Could not connected")

while True:
    text = irc.get_response()

    # TODO: fro action ( if message has a command )

irc.close()