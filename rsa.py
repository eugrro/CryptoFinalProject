""" RSA implementation. """
import secrets
from sympy.ntheory import isprime
from sha1 import sha1


def decimal_to_binary(N, pad):
    """ converts a nonnegative integer N in base 10 to a list of bits corresponding to the binary representation
        of N. Pads with leading 0s until it's of length pad; assumes that lg N <= pad """
    if N == 0:
        return [0] * pad

    L = []
    while N > 0:
        L.append(N % 2)  # figure out the current last bit
        N = N // 2  # remove the last bit from N

    if pad != -1:
        return [0] * (pad - len(L)) + L[::-1]  # reverse the list
    else:
        return L[::-1]


def modular_exponentiation(base, exp, modulus):
    """ computes base^exp mod modulus using repeated squaring; needed for encryption/decryption in a reasonable
        amount of time """
    binary_rep = decimal_to_binary(exp, -1)[::-1]
    answer = 1
    for i in range(0, len(binary_rep)):
        if binary_rep[i] == 1:
            answer = (answer * base) % modulus
        base = (base ** 2) % modulus

    return answer


def multiplicative_inverse(m, n):
    """ computes A in the equation Am + Bn = 1 for gcd(m, n) = 1 """
    larger, smaller = m, n
    prev_A, A = 1, 0

    while smaller != 0:
        quotient = larger // smaller
        larger, smaller = smaller, larger - quotient*smaller
        prev_A, A = A, prev_A - quotient*A

    return prev_A % n


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def make_prime(bits):
    """ makes a random prime number with the specified number of bits. The first bit
        is going to be a 1 """
    p = 2**(bits - 1) + secrets.randbits(bits - 1)
    while not isprime(p):
        p = 2 ** (bits - 1) + secrets.randbits(bits - 1)
    return p


def rsa_encrypt(message, public_key):
    """ public_key is in the form (e, pq) where e is the exponent that the message is raised to for encryption
        and pq is the product of the primes

        returns the corresponding ciphertext """
    return modular_exponentiation(message, public_key[0], public_key[1])


def rsa_decrypt(ciphertext, public_key, private_key):
    """ public_key is in the form it was above, private_key is just the decryption exponent
        returns the corresponding plaintext """
    return modular_exponentiation(ciphertext, private_key, public_key[1])


def make_key_pair():
    """ Makes a 2048-bit RSA key pair; returns (p, q, e, d) """
    p, q = make_prime(1024), make_prime(1024)
    e = 0
    while gcd(e, (p - 1)*(q - 1)) != 1:
        e = secrets.randbelow((p - 1)*(q - 1))
    d = multiplicative_inverse(e, (p - 1)*(q - 1))

    return p, q, e, d


def mask_generation_function(message, output_length):
    """ MGF based on SHA-1. """
    pass

def oaep(message, k0, k1, p, q):
    """ See https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding ;
        this makes this RSA implementation semantically secure. This needs to be
        used before actually encrypting the message. """
    # message is 1024 bits in length; number of bits in RSA modulus is floor(lg(p) + lg(q));
    #
    r = secrets.randbits(k0)



def inverse_oaep(random_message, k0, k1):
    """ Given X || Y from above and k0, k1, recovers the original message. """
    Y = random_message % 2**k0
    X = random_message >> k0
    r = Y ^ H(X)
    message_with_zeroes = X ^ G(r)
    return message_with_zeroes >> k1


if __name__ == "__main__":
    for i in range(1, 1000):
        print(i)
        p, q, e, d = make_key_pair()
        ctext = rsa_encrypt(12345, (e, p*q))
        assert(rsa_decrypt(ctext, (e, p*q), d) == 12345)




