import rsa
import hmac_ours
import socket
import aes
import text_to_number

def recMsg(socket, size):
	data = socket.recv(size)
	#do some kind of decode
	return data.decode()

if __name__ == "__main__":
	port = 65432#int(input("Port: "))
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind(('127.0.0.1',port))
	server.listen()
	while True:
		client, addr = server.accept()
		print("Client at {} connected".format(addr))

		client.sendall("You've connected to the Bank".encode())
		clientPubkey = list(map(int,recMsg(client, 4096).split(",")))
		
		aesKey = aes.generate_key()
		hmacKey = hmac_ours.generate_key()
		
		msg = chr(16) + aesKey + chr(16) + hmacKey
		msg += hmac_ours.hexToText(hmac_ours.hmac(msg,hmacKey))
		
		keys = rsa.rsa_encrypt(msg, clientPubkey)
		client.sendall(keys.encode())

		userInfo = recMsg(client, 4096)
		userInfo = rsa.rsa_decrypt(userInfo,clientPubkey,clientPubkey[0])
		length1 = ord(userInfo[0])
		length2 = ord(userInfo[length1+1])
		username = userInfo[1:length1+1]
		password = userInfo[length1+2:-20]
		
		if hmac_ours.hexToText(hmac_ours.hmac(userInfo[:-20],hmacKey)) != userInfo[-20:]:
			print("Tampering found, hash isn't equal")
			break;




