#!/usr/bin/env python3

# layout of output like is like so:
# two bytes, total length of the rest of the file, not including these two bytes (default: 44 or hex 002c)
# two bytes, odoh version.
# two bytes, total length of the rest of the file, not including these two bytes (default: 40 or hex 0028)
# six bytes, kem/kdc/aead ids
# 32? bytes, public key
# 
# for a total of 46 bytes.

import argparse, sys

parser = argparse.ArgumentParser()
parser.add_argument('--file', '-f', required=True)
parser.add_argument('--out', '-o', required=True)

args = parser.parse_args()

KEM_ID_BYTES = b'\x00\x20'
KDF_ID_BYTES = b'\x00\x01'
AEAD_ID_BYTES = b'\x00\x01'

ODOH_VERSION_BYTES = b'\xff\x06'

DEFAULT_FIRST_LEN_BYTES = b'\x00\x2c'
DEFAULT_SECOND_LEN_BYTES = b'\x00\x28'

with open(args.out, 'wb') as outfile:
    outfile.write(DEFAULT_FIRST_LEN_BYTES)
    outfile.write(ODOH_VERSION_BYTES)
    outfile.write(DEFAULT_SECOND_LEN_BYTES)
    outfile.write(KEM_ID_BYTES)
    outfile.write(KDF_ID_BYTES)
    outfile.write(AEAD_ID_BYTES)
    with open(args.file, 'rb') as infile:
        pubkeybytes = infile.read()
        assert(len(pubkeybytes) == 32)
        outfile.write(pubkeybytes)
