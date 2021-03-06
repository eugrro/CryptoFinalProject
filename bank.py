import rsa
import hmac_ours
import socket
import aes
import text_to_number
import sha1
import secrets

def recMsg(socket, size):
    data = socket.recv(size)
    #do some kind of decode
    return data.decode()

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
                conn.sendall("You've connected to the Bank".encode())
                clientPubkey = list(map(int,recMsg(conn, 4096).split(",")))
                
                aesKey = aes.generate_key()
                iv = hmac_ours.hexToText(sha1.run(str(secrets.randbelow(4096)))[:32])
                hmacKey = hmac_ours.generate_key()
                msg = chr(16) + aesKey + chr(16) + hmacKey + chr(16) + iv
                msg += hmac_ours.hexToText(hmac_ours.hmac(msg,hmacKey))
                
                keys = rsa.rsa_encrypt(msg, clientPubkey)
                conn.sendall(keys.encode())

                userInfo = recMsg(conn, 4096)

                userInfo = aes.aes_cbc_decrypt(userInfo,aesKey,iv)
                length1 = ord(userInfo[0])
                length2 = ord(userInfo[length1+1])
                username = userInfo[1:length1+1]
                password = userInfo[length1+2:length1+1+length2+1]

                if hmac_ours.hexToText(hmac_ours.hmac(userInfo[:-20],hmacKey)) != userInfo[-20:]:
                    print("Tampering found, hash isn't equal")
                else:
                    print("User accepted")
                    msg = "SUCCESS" + hmac_ours.hexToText(hmac_ours.hmac("SUCCESS",hmacKey))
                    auth = aes.aes_cbc_encrypt(msg,aesKey,iv)
                    conn.sendall(auth.encode())

                    while True:
                        data = recMsg(conn, 4096)
                        data = aes.aes_cbc_decrypt(data,aesKey,iv)
                        mac = data[-20:]
                        data = data[:-20]

                        if hmac_ours.hexToText(hmac_ours.hmac(data,hmacKey)) != mac:
                            print("Tampering found, hash isn't equal")
                            break

                        if not data or data == 'q':
                            break
                        print("Bank received: " + data)
                        ret = self.parseCommand(data)
                        print("Sending Back: " + ret)
                        ret += hmac_ours.hexToText(hmac_ours.hmac(ret,hmacKey))
                        ret = aes.aes_cbc_encrypt(ret, aesKey, iv)
                        conn.sendall(ret.encode())

    def depositAmount(self, amount):
        self.userTotal += float(amount)

    def withdrawAmount(self, amount):
        if self.userTotal >= float(amount):
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
            return "Unknown transaction has been received, please try again"


bank()
