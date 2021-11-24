import socket

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server


def displayHeader():
    print("Welcome to the ATM")
    print("Your valid oprations are deposit, withdraw, and view balance")
    print("To withdraw, write <w amount> (for example: w 20)")
    print("To deposit, write <d amount> (for example: d 15.25)")
    print("To view balance, write <v> (for example: v)")


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    displayHeader()
    while True:
        userInput = input("Enter a message to send: ")
        s.sendall(str.encode(userInput))
        recieveData = s.recv(1024)
        print(recieveData.decode())
