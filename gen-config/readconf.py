#!/usr/bin/env python3
import argparse
import random
from key import KEY
import salsa20

def decrypt(encryptedBytes):
    nonce = encryptedBytes[:8]
    ciphertext = encryptedBytes[8:]

    decrypted = salsa20.s20_crypt(KEY, nonce, ciphertext)
    return decrypted.decode('utf-8')


def parseFile(path):
    with open(path, 'rb') as infile:
        return decrypt(infile.read())

def parseHex(hexString):
    return decrypt(bytes.fromhex(hexString))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='Config file to decode')
    parser.add_argument('-x', '--hex', help='Hex string representing the config')
    args = parser.parse_args()

    if args.file and args.hex:
        print('Parameters f (file) and x (hex) are mutually exclusive!')

    if args.file:
        decrypted = parseFile(args.file)
    elif args.hex:
        decrypted = parseHex(args.hex)
    else:
        print('Either parameter f (file) or x (hex) is required.')

    print(decrypted)
        

if __name__ == "__main__":
    main()
