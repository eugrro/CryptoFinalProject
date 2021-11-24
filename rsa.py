""" RSA implementation. Not sure why, but it seems to work whenever the string to encrypt is <= 128 characters;
it fails with some probability otherwise. """

import secrets
from sympy.ntheory import isprime
from sha1 import sha1
from text_to_number import text_to_number
from text_to_number import number_to_text


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
    while not all(isprime(p) for i in range(1, 10)):  # random primality test, might as well run it 10 times
        p = 2 ** (bits - 1) + secrets.randbits(bits - 1)
    return p


def rsa_encrypt(message, public_key):
    """ public_key is in the form (e, pq) where e is the exponent that the message is raised to for encryption
        and pq is the product of the primes. Message is a normal string which will be encrypted in
        128-character (1024-bit) chunks in CBC mode.

        returns the corresponding ciphertext. """

    message_blocks = [secrets.randbits(2046)]  # IV for CBC

    for i in range(0, len(message)//128):
        message_blocks.append(text_to_number(message[i:i+128]))
    if len(message) % 128 != 0:
        message_blocks.append(text_to_number(message[-(len(message) % 128):]))

    # OAEP pad the message (each block)
    for i in range(1, len(message_blocks)):
        message_blocks[i] = oaep(message_blocks[i], 275, 748, public_key[1])

    # encrypt in CBC mode with IV being a random string, encrypted at the beginning
    for i in range(1, len(message_blocks)):
        # encrypt the individual blocks
        message_blocks[i] = modular_exponentiation(message_blocks[i] ^ message_blocks[i - 1], public_key[0], public_key[1])
    message_blocks[0] = modular_exponentiation(message_blocks[0], public_key[0], public_key[1])  # encrypt the IV

    # return the ciphertext as a text string
    ctext = 0
    for i in range(0, len(message_blocks)):
        ctext = ctext << 2047
        ctext += message_blocks[i]

    return number_to_text(ctext)


def rsa_decrypt(ciphertext, public_key, private_key):
    """ public_key is in the form it was above, private_key is just the decryption exponent
        returns the corresponding plaintext. Ciphertext is a normal text string """
    ciphertext = text_to_number(ciphertext)

    # convert ciphertext to 2047-bit blocks; for CBC, the IV is the bits right at the start of the number
    ciphertext_blocks = []
    while ciphertext > (1 << 2047):
        ciphertext_blocks.append(ciphertext % (1 << 2047))
        ciphertext = ciphertext >> 2047

    ciphertext_blocks = [ciphertext] + list(reversed(ciphertext_blocks))
    # decrypt in CBC mode with IV being known
    ciphertext_blocks[0] = modular_exponentiation(ciphertext_blocks[0], private_key, public_key[1])  # decrypt the IV
    for i in range(len(ciphertext_blocks) - 1, 0, -1):
        ciphertext_blocks[i] = modular_exponentiation(ciphertext_blocks[i], private_key, public_key[1]) ^ ciphertext_blocks[i - 1]

    # un-OAEP pad the message to get back to 1024-bit blocks of plaintext
    for i in range(1, len(ciphertext_blocks)):
        ciphertext_blocks[i] = inverse_oaep(ciphertext_blocks[i], 275, 748, public_key[1])

    # convert the blocks back to plaintext
    return "".join(number_to_text(ciphertext_blocks[i]) for i in range(1, len(ciphertext_blocks)))


def make_key_pair():
    """ Makes a 2047-bit RSA key pair; returns (p, q, e, d) """
    p, q = make_prime(1024), make_prime(1024)
    while len(decimal_to_binary(p*q, -1)) == 2048:  # when pq was 2048 bits, it was giving me problems. Unsure why
        p, q = make_prime(1024), make_prime(1024)

    e = 0
    while gcd(e, (p - 1)*(q - 1)) != 1:
        e = secrets.randbelow((p - 1)*(q - 1))
    d = multiplicative_inverse(e, (p - 1)*(q - 1))

    return p, q, e, d


def mask_generation_function(message, output_length):
    """ MGF based on SHA-1. SHA-1 returns a hash of length 20 bytes.
        Returns a 'hash' of output_length BITS. Message is a number """
    output = 0
    for i in range(0, (output_length // 160) + 1):
        output = (output << 160) + int(sha1(number_to_text(message + i)), 16)
    # now we probably have more bytes than we want; just cut off the bits we don't want
    return output >> 160 - (output_length % 160)


def oaep(message, k0, k1, n):
    """ See https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding ;
        this makes this RSA implementation semantically secure. This needs to be
        used before actually encrypting the message. Pads a 1024-bit message (may have leading 0's) to 2047 bits.
        k0 and k1 are fixed in actual encryption to be 275 and 748, as that's what a RNG told me. """
    r = secrets.randbits(k0)
    n_bits = len(decimal_to_binary(n, -1)) - 1  # the number of bits we want to expand the message to
    X = (message << k1) ^ mask_generation_function(r, n_bits - k0)
    Y = r ^ mask_generation_function(X, k0)
    return (X << k0) + Y


def inverse_oaep(random_message, k0, k1, n):
    """ Given X || Y from above and k0, k1, recovers the original message. """
    n_bits = len(decimal_to_binary(n, -1)) - 1  # the number of bits we want to expand the message to
    Y = random_message % (1 << k0)  # the last k0 bits of the message
    X = random_message >> k0  # the first (n_bits - k0) bits of the message, with k0 0's added on
    r = Y ^ mask_generation_function(X, k0)
    message_with_zeroes = X ^ mask_generation_function(r, n_bits - k0)
    return message_with_zeroes >> k1


if __name__ == "__main__":

    table = []
    other_table = []
    for i in range(0, 2**10):
        ptext = number_to_text(i)
        p, q, e, d = make_key_pair()
        print(ptext == rsa_decrypt(rsa_encrypt(ptext, (e, p*q)), (e, p*q), d))

