#!/usr/bin/env python3
import argparse
import random
from key import KEY
import salsa20

def genConfig(username, password, groupSids = []):
    lines = []
    lines.append(f'username={username}')
    lines.append(f'password={password}')
    for sid in groupSids:
        lines.append(f'groupsid={sid}')

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', required=True, type=str, help='Username')
    parser.add_argument('-p', '--password', required=True, type=str, help='Password')
    parser.add_argument('-s', '--group-sid', action='append', type=str, help='Group SID (can be specified multiple times)')
    parser.add_argument('-n', '--name', type=str, help='Name')
    parser.add_argument('-x', '--hex', action='store_true', help='Ecode config hexadecimal (useful to embed a fallback default config into a binary)')

    args = parser.parse_args()
    confname = args.name or 'pwn.txt'

    config = genConfig(args.username, args.password, args.group_sid or [])
    print(f'The encoded config is written to {confname}')
    print('Here is your config in plain:\n')
    print(config)

    nonce = [random.randint(0, 255) for _ in range(8)]

    ciphertext = salsa20.s20_crypt(KEY, nonce, config.encode())
    data = bytearray(bytes(nonce) + ciphertext)

    if (args.hex):
        print()
        print('Here is the encoded config in hex:')
        print(''.join([format(byte, '02x') for byte in data]))

    with open(confname, 'wb') as encodedConf:
        encodedConf.write(data)

if __name__ == "__main__":
    main()
