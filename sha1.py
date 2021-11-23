

#nonlinear function for round
def f(t,B,C,D):
	return 0

#returns left shift of input by x bits
def left_rotate(input, x):
	return (input << x)|(input >> (32-x)) & 0xffffffff

def chunk(msg, size):
	return [msg[i:i+size] for i in range(0, len(msg), size)]

def pad(msg):
	msg = ' '.join("{:08b}".format(ord(x)) for x in msg).replace(" ","")
	if len(msg)%8 == 0:
		msg+='1'
	while len(msg)%512 != 448:
		msg += '0'

	return msg

def sha1(msg):
	h0 = 0x67452301
	h1 = 0xefcdab89
	h2 = 0x98badcfe
	h3 = 0x10325476
	h4 = 0xc3d2e1f0

	msgLen = len(msg)*8
	msg = pad(msg)
	msg += "{:064b}".format(msgLen)
	chunks = chunk(msg,512)

	for c in chunks:
		smallChunk = chunk(c,32)
		w = []
		for sc in smallChunk:
			w.append(int(sc,2))

		for i in range(16,80):
			w.append(left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1))

		a,b,c,d,e = h0,h1,h2,h3,h4

		for i in range(80):
			if i < 20:
				f = d ^ (b& (c ^ d))
				k = 0x5A827999
			elif i < 40:
				f = (b & c) | ((~b) & d)
				k = 0x6ED9EBA1
			elif i < 60:
				f = (b & c) ^ ((~b) & d)
				k = 0x8F1BBCDC
			else:
				f = b ^ c ^ d
				k = 0xCA62C1D6

			a,b,c,d,e = left_rotate(a,5)+f+e+k+w[i], a, left_rotate(b,30), c, d
		h0 = (a + h0) & 0xffffffff
		h1 = (b + h1) & 0xffffffff
		h2 = (c + h2) & 0xffffffff
		h3 = (d + h3) & 0xffffffff
		h4 = (e + h4) & 0xffffffff


	return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

def run(msg):
	return sha1(msg)

if __name__ == "__main__":
	print(run('0'))