import rsa
import hmac_ours
import socket
import os
import aes
import text_to_number

def recMsg(socket, size):
	data = socket.recv(size)
	#do some kind of decode
	return data.decode()

if __name__ == "__main__":
	host = '127.0.0.1' #input("Bank IP: ")
	port = 65432 #int(input("Port: "))
	#username = input("Username: ")
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client.connect((host,port))

	key_exchange_msgs = []
	p,q,e,d =  rsa.make_key_pair()
	n = p*q

	# pub key = {e, n}
	# priv key = {d, p, q}

	### BANK -- sends hello welcome to bank
	print(recMsg(client, 4096))


	#send public key to Bank
	msg = "{},{}".format(e,n)
	print(e)
	print(n)
	client.sendall(msg.encode())
	print("RSA public key sent to Bank",flush=True)

	
	data = recMsg(client, 4096)
	print(int(data))
	keys = rsa.rsa_decrypt(int(data),[e,n],d)
	keys = text_to_number.number_to_text(keys)
	print(keys)
	keyArray = keys.split(str(ord(",")))
	print(keyArray)
	#keys = text_to_number.number_to_text(keys)
	#print(keys)
	#print(ord(keys[0]))
	#length1 = ord(keys[0])
	#length2 = ord(data[length1+1])
	aesKey = keyArray[0]  #keys[1:length1+1]
	macKey = keyArray[1]  #[length1+2:-20]
	if hmac_ours.hexToText(hmac_ours.hmac(keys[:-20], macKey)) != keys[-20:]:
		print("Tampering found, hash isn't equal")
		
	else:
		username = input("Username: ")
		password = input("Password: ")
		msg = chr(len(username))+username + chr(len(password))+password
		msg += hmac_ours.hexToText(hmac_ours.hmac(msg, macKey))
		final = rsa.rsa_encrypt(msg, (d,n))
		client.sendall(final.encode())

