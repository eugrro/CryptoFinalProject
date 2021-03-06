import rsa
import hmac_ours
import socket
import os
import aes
import text_to_number
import sha1
import secrets

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server


def displayHeader():
    print("Welcome to the ATM")
    print("Your valid oprations are deposit, withdraw, and view balance")
    print("To withdraw, write <w amount> (for example: w 20)")
    print("To deposit, write <d amount> (for example: d 15.25)")
    print("To view balance, write <v> (for example: v)")
    print("To quit, write <q> (for example: q)")

def recMsg(socket, size):
    data = socket.recv(size)
    return data.decode()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    displayHeader()
    while True:
        key_exchange_msgs = []
        p,q,e,d =  rsa.make_key_pair()
        n = p*q

        # pub key = {e, n}
        # priv key = {d, p, q}

        ### BANK -- sends hello welcome to bank
        print(recMsg(s, 4096))


        #send public key to Bank
        msg = "{},{}".format(e,n)
        s.sendall(msg.encode())
        print("RSA public key sent to Bank",flush=True)

        
        data = recMsg(s, 4096)
        keys = rsa.rsa_decrypt(data,[e,n],d)

        length1 = ord(keys[0])
        length2 = ord(keys[length1+1])
        length3 = ord(keys[length1+1+length2+1])
        aesKey = keys[1:length1+1]
        hmacKey = keys[length1+2:length1+1+length2+1]
        iv = keys[length1+1+length2+2:length1+1+length2+1+length3+1]

        if hmac_ours.hexToText(hmac_ours.hmac(keys[:-20], hmacKey)) != keys[-20:]:
            print("Tampering found, hash isn't equal")
            
        else:
            username = 'Aaron' #input("Username: ")
            password = '1234'  #input("Password: ")
            msg = chr(len(username)) + username + chr(len(password)) + password
            msg += hmac_ours.hexToText(hmac_ours.hmac(msg, hmacKey))
            final = aes.aes_cbc_encrypt(msg, aesKey, iv)
            s.sendall(final.encode())

            #receive auth from bank
            auth = recMsg(s, 4096)
            auth = aes.aes_cbc_decrypt(auth,aesKey,iv)
            mac = auth[-20:]
            auth = auth[:-20]
            if hmac_ours.hexToText(hmac_ours.hmac(auth, hmacKey)) != mac:
                print("Tampering found, hash isn't equal")
                auth = ""
            if auth == "SUCCESS":
                quit = 0
                while True:
                    userInput = input("Enter a message to send: ")
                    
                    userInput += hmac_ours.hexToText(hmac_ours.hmac(userInput, hmacKey))
                    s.sendall(aes.aes_cbc_encrypt(userInput, aesKey, iv).encode())
                    if userInput[:-20] == "q":
                        quit = 1
                        break
                    receiveData = recMsg(s, 4096)
                    receiveData = aes.aes_cbc_decrypt(receiveData,aesKey,iv)
                    mac = receiveData[-20:]
                    receiveData = receiveData[:-20]
                    if hmac_ours.hexToText(hmac_ours.hmac(receiveData, hmacKey)) != mac:
                        print("Tampering found, hash isn't equal")
                        break
                    print(receiveData)
                if quit == 1:
                    break
            else:
                print("Authorization failed, please log in again")
