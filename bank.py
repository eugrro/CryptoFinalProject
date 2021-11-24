import socket


class bank(object):
    def __init__(self) -> None:
        super().__init__()

        HOST = '127.0.0.1'
        PORT = 65432
        self.userTotal = 0
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

            s.bind((HOST, PORT))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    print("Bank recieved: " + data.decode())
                    ret = self.parseCommand(data.decode())
                    print("Sending Back: " + ret)
                    conn.sendall(str.encode(ret))

    def depositAmount(self, amount):
        self.userTotal += float(amount)

    def withdrawAmount(self, amount):
        if self.userTotal > float(amount):
            self.userTotal -= float(amount)
            return 1
        else:
            return -1

    def parseCommand(self, command):
        userCommand = command.split()
        if userCommand[0] == "v":
            return "Your current balance is: " + str(round(self.userTotal, 2))
        elif userCommand[0] == "d":
            self.depositAmount(userCommand[1])
            return str(userCommand[1]) + " dollars have been sucessfully added to your account"
        elif userCommand[0] == "w":
            res = self.withdrawAmount(userCommand[1])
            if res == 1:
                return str(userCommand[1]) + " dollars have been sucessfully withdrawn from your account"
            else:
                return "Cannot withdraw " + str(userCommand[1]) + " dollars. Insufficient funds"
        else:
            return "Unknown transaction has been recieved, please try again"


bank()
