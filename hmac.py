import sha1

def hexToText(x):
	tmp =''
	for i in range(0,len(x),2):
		val = x[i:i+2]
		tmp += chr(int(val,16))
	return tmp

def textToHex(x):
	tmp = []
	for i in x:
		tmp.append(ord(i))
	return tmp

def xorHexList(a,b):
	return [a[i]^b[i] for i in range(len(a))]

def hmac(msg, key):
	opad = [0x5c]*64
	ipad = [0x36]*64

	if 8*len(key) > 64:
		key = hexToText(sha1.run(key))

	if 8*len(key) < 64:
		while 8*len(key) < 64:
			key += chr(0)

	okey = hexToText(''.join(map(str,xorHexList(textToHex(key), opad))))
	ikey = hexToText(''.join(map(str,xorHexList(textToHex(key), ipad))))

	hash1 = hexToText(sha1.run(ikey + msg))
	hash2 = sha1.run(okey+hash1)
	return hash2
	

if __name__ == "__main__":
	print(hmac("Test hmac for crypto", "CSCI 4230 T/Thr"))
