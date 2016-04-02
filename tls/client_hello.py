#!/usr/bin/python3.5
# -*-coding:utf-8 -*
import struct
import binascii
from .utilities import *

"""Module which handle client hello handshake protocol for TLS1.2"""

def handle_client_hello(file, prefix, data):
	# cursor: variable to browse all TLS data
	# we initialiez it to 34 to browse the 5 first TLS parameters
	cursor = 37
	max_tls_version, unix_time, random_value,\
		session_id_length, cipher_suites_length = struct.unpack('! 2s 4s 28s B H', data[:cursor])

	file.write(prefix + 'Max TLS Version: {},'
						' Unix Time: {}\n'.format(tls_version(max_tls_version), get_str_value(unix_time)))
	file.write(prefix + 'Random Bytes: {}\n'.format(get_str_value(random_value)))
	file.write(prefix + 'Session Id length: {},'
						' Cipher Suites Length: {}\n'.format(session_id_length, cipher_suites_length))
	# Course all cryptographic suites
	if cipher_suites_length % 2 != 0:
		cipher_suites_length += 1
	search = '! ' + '2s' * (cipher_suites_length // 2)
	cipher_suites = struct.unpack(search, data[cursor: cursor + cipher_suites_length])
	for cipher in cipher_suites:
		file.write(TAB_5 + 'Cipher Suite: {}\n'.format(get_cipher_suite(cipher)))
	# Compression method
	cursor += cipher_suites_length
	compression_method_length, compression_method = struct.unpack('! B B', data[cursor: cursor + 2])
	file.write(prefix + 'Compression Method Length: {}\n'.format(compression_method_length))
	file.write(prefix + 'Compression Method: {}\n'.format(compression_method))
	# Extensions
	cursor += 2
	extensions_length = struct.unpack('! H', data[cursor: cursor + 2])
	extensions_length = extensions_length[0]
	file.write(prefix + 'Extensions Length: {}\n'.format(extensions_length))

	#Browse all extensions
	cursor += 2
	# counter to browse the extension list
	i = 0
	while i < extensions_length:
		extension_type, extension_length = struct.unpack('! H H', data[cursor : cursor + 4])
		file.write(TAB_5 + 'Extension Type: {}\n'.format(get_extension_type(extension_type)))
		file.write(TAB_5 + 'Extension Length: {}\n'.format(extension_length))
		cursor += 4
		i += 4
		raw_extension_value = data[cursor: cursor + extension_length]
		get_extension_informations(file, raw_extension_value, extension_length, extension_type)
		cursor += extension_length
		i += extension_length


	file.write('Client Hello Data:\n')
	file.write(format_multi_line(TAB_5, data))