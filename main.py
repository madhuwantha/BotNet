import BotNet

if __name__ == '__main__':
    b = BotNet.BotNet(networks=["192.168.8.0/24"])
    # b.findDevices()
    # b.findVulnerabilities()
    b.dictionaryAttack()