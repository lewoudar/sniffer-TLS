#!/usr/bin/python3.5
# -*-coding:utf-8 -*
import struct
import binascii
from .utilities import *

"""Module which handle server hello handshake protocol for TLS1.2"""

def handle_server_hello(file, prefix, data):
	# cursor: variable to browse all TLS data
	# we initialise it to 37 to browse the 5 first TLS parameters
	cursor = 37
	max_tls_version, unix_time, random_value,\
		session_id_length, cipher_suite = struct.unpack('! 2s 4s 28s B 2s', data[:cursor])
	file.write(prefix + 'Max TLS Version: {},'
						' Unix Time: {}\n'.format(tls_version(max_tls_version), get_number(unix_time)))
	file.write(prefix + 'Random Bytes: {}\n'.format(get_number(random_value)))
	file.write(prefix + 'Session Id length: {}\n'.format(session_id_length))
	file.write(prefix + 'Cipher Suite: {}\n'.format(get_cipher_suite(cipher_suite)))
	# Compression Method
	compression_method = struct.unpack('! B', data[cursor: cursor + 1])[0]
	file.write(prefix + 'Compression Method: {}\n'.format(compression_method))
	# Extensions
	cursor += 1
	extensions_length = struct.unpack('! H', data[cursor : cursor + 2])[0]
	file.write(prefix + 'Extensions Length: {}\n'.format(extensions_length))