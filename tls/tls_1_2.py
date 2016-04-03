#!/usr/bin/python3.5
# -*-coding:utf-8-*

""" Module which permit analysis of TLS1.2 protocol"""
import struct
from .utilities import *
from .client_hello import *
from .server_hello import *
from .certificate import *
from .server_key_exchange import *
from .client_key_exchange import *
from .new_session_ticket import *


# TLS packet
def tls_packet(file, prefix, data):

	content_type, min_tls_version, length = struct.unpack('! B 2s H', data[:5])
	file.write(prefix + 'TLS packet:\n')
	prefix = '\t' + prefix
	file.write(prefix + 'Content Type: {}, TLS Version: {},'
						' Length: {}\n'.format(content_type, tls_version(min_tls_version), length))

	# Handshake protocol
	if content_type == 22:
		handshake_type, handshake_length = struct.unpack('! B I', data[5:10])
		handshake_length >>= 8
		file.write(prefix + 'Handshake Type: {}, Handshake Length: {}\n'.format( \
			get_handshake_type(handshake_type), handshake_length))

		# Client Hello
		if handshake_type == 1:
			handle_client_hello(file, prefix, data[9:])

		# Server Hello
		if handshake_type == 2:
			handle_server_hello(file, prefix, data[9:])

		# Certificate
		if handshake_type == 11:
			handle_certificate(file, prefix, data[9:])

		# Server key exchange
		if handshake_type == 12:
			handle_server_key_exchange(file, prefix, data[9:])

		# Client key exchange
		if handshake_type == 16:
			handle_client_key_exchange(file, prefix, data[9:])

		# New Session Ticket
		if handshake_type == 4:
			handle_new_session_ticket(file, prefix, data[9:])

	# Change Cipher Spec (20) or Encrypted Alert (21) or Application Data (23)
	if content_type in [20, 21, 23]:
		message = str(binascii.hexlify(data[5 : 5 + length]))[2:-1]
		file.write(prefix + 'Message: {}\n'.format(message))

