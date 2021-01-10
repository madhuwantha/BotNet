from IotBot.irc_class import IRC

server = "10.50.60.181"
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