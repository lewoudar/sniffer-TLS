#!/usr/bin/python3.5
# -*-coding:utf-8 -*
import struct
from .utilities import *

"""Module which handle server key exchange handshake protocol for TLS1.2"""

def handle_server_key_exchange(file, prefix, data):
	# cursor: variable to browse all TLS data
	cursor = 1
	# Curve Type
	curve_type = struct.unpack('! B', data[:cursor])[0]
	file.write(prefix + 'Curve Type: {}\n'.format(get_ec_curve_type(curve_type)))
	# Named Curve
	named_curve = struct.unpack('! H', data[cursor : cursor + 2])[0]
	file.write(prefix + 'Named Curve: {}\n'.format(get_elliptic_curve(named_curve)))
	# Public Key Length
	cursor += 2
	pub_key_length = struct.unpack('! B', data[cursor: cursor + 1])[0]
	file.write(prefix + 'Public Key Length: {}\n'.format(pub_key_length))
	# Public Key
	cursor += 1
	public_key = struct.unpack('! ' + 's' * pub_key_length, data[cursor : cursor + pub_key_length])
	file.write(prefix + 'Public Key: {}\n'.format(get_string(public_key)))
	# Signature Hash algorithm
	cursor += pub_key_length
	file.write(prefix + 'Signature Hash Algorithm:\n')
	hash_algorithm, signature_algorithm = struct.unpack('! B B', data[cursor, cursor + 2])
	file.write('\t' + prefix + 'Hash Algorithm: {}\n'.format(get_hash_method(hash_algorithm)))
	file.write('\t' + prefix + 'Signature Algorithm: {}\n'.format(get_signature_method(signature_algorithm)))
	# Signature Length
	cursor += 2
	signature_length = struct.unpack('! H', data[cursor : cursor + 2])[0]
	file.write(prefix + 'Signature Length: {}\n'.format(signature_length))
	# Signature
	cursor += 2
	signature = struct.unpack('! ' + 's' * signature_length, data[cursor : cursor + signature_length])
	file.write(prefix + 'Signature: {}\n'.format(get_string(signature)))