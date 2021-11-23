from Crypto.Util import number
import random

def lcm(x,y):
	if x > y:
		big = x
	else:
		big = y
	while(True):
		if big%x == 0 and big%y == 0:
			return big
		big += 1

#extended euclidean alg
def extEuc(a, b):
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = extEuc(b % a, a)
		return g, x - (b // a) * y, y

def modInv(a,b):
	g,x,y = extEuc(a,b)
	if g != 1:
		return -1
	else:
		return x%b

def L(x,n):
	return (x-1%n)/n

def paillier(bits):
	u = -1
	while u == -1:
		p = number.getPrime(bits)
		q = number.getPrime(bits)
		while p == q:
			q = number.getPrime(bits)
		n = p*q
		lamb = lcm(p-1,q-1)
		g = random.randint(1,n**2)
		u = modInv( L( pow(g,lamb,n**2), n), n)
	return g,p,q,lamb,int(u)

if __name__ == "__main__":
	g,p,q,lamb,u = paillier(10)
	print(g,p,q,lamb,u)

	m = 25
	n = p*q
	u1 = random.randint(1,n**2)
	c = pow(g,m,n**2)*pow(u,n,n**2)%n**2
	print(c)
	m = L(pow(c,lamb,n**2),n)%n * u%n
	print(m)