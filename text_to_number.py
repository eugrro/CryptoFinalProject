import numpy


def text_to_number(word):
    """ Converts the word to a number. """
    ret = 0
    for i in range(0, len(word)):
        ret = (ret << 8) + ord(word[i])
    return ret


def number_to_text(number):
    """ Converts a number to a plaintext string. """
    ret = ""
    while number > 0:
        ret += chr(number % 256)
        number = number >> 8
    return ret[::-1]


if __name__ == "__main__":
    print(text_to_number(number_to_text(234234)))
    print(number_to_text(text_to_number("asdf")))
