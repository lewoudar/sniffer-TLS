#!/usr/bin/python3.5
# -*-coding:utf-8 -*
import struct
import binascii
from .utilities import *

"""Module which handle client key exchange handshake protocol for TLS1.2"""

def handle_client_key_exchange(file, prefix, data):
	# cursor: variable to browse all TLS data
	cursor = 1
	# Public Key Length
	pub_key_length = struct.unpack('! B', data[:cursor])[0]
	file.write(prefix + 'Public Key Length: {}\n'.format(pub_key_length))
	# Public Key
	# I use binascii.hexlify to have an hexadecimal message which is in my mind
	# much readable
	public_key = str(binascii.hexlify(data[cursor : cursor + pub_key_length]))[2:-1]
	file.write(prefix + 'Public Key: {}\n'.format(public_key))