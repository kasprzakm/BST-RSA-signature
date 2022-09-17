import psutil
import hashlib
import time


# Reads processor's current frequency,
# converts it to UTF-8 string,
# then hashes with SHA256.
# Returns integer value of random binary.

def bitstring_to_bytes(s):
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')


def rando(amount_of_bits: int = 8):
    i = 0
    bits = list()
    # result = 0
    result2 = ''

    while i < amount_of_bits:
        frequency = str(psutil.cpu_freq().current).encode('ascii')
        hasher = hashlib.sha256()
        hasher.update(frequency)
        bits.append(int(hasher.hexdigest(), 16) & 1)
        i += 1
        print(i)
        time.sleep(0.0001)

    # for i in range(len(bits)):
    #    result += bits[-(i+1)] * (2 ** i)

    for i in bits:
        result2 += str(i)

    print('CTRL')

    result_encoded = result2.encode('ascii')
    return bytes(result_encoded)
    # return result2