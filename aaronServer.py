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
		iv = hmac_ours.hexToText(sha1.run(str(secrets.randbelow(0,4096)))[:32])
		hmacKey = hmac_ours.generate_key()
		msg = chr(16) + aesKey + chr(16) + hmacKey + chr(16) + iv
		msg += hmac_ours.hexToText(hmac_ours.hmac(msg,hmacKey))
		
		keys = rsa.rsa_encrypt(msg, clientPubkey)
		client.sendall(keys.encode())

		userInfo = recMsg(client, 4096)
		print("+++++++++++++++++++++++")
		print(userInfo)
		userInfo = aes.aes_cbc_decrypt(userInfo,aesKey,iv)
		length1 = ord(userInfo[0])
		length2 = ord(userInfo[length1+1])
		username = userInfo[1:length1+1]
		password = userInfo[length1+2:length1+1+length2+1]
		if hmac_ours.hexToText(hmac_ours.hmac(userInfo[:-20],hmacKey)) != userInfo[-20:]:
			print("Tampering found, hash isn't equal")
			break;
		else:
			print("User accepted")




