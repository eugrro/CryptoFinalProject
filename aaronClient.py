import rsa
import hmac_ours
import socket
import os
import aes
import text_to_number
import sha1
import random

def recMsg(socket, size):
	data = socket.recv(size)
	#do some kind of decode
	return data.decode()

if __name__ == "__main__":
	host = '127.0.0.1' #input("Bank IP: ")
	port = 65432 #int(input("Port: "))
	
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
		client.sendall(final.encode())

