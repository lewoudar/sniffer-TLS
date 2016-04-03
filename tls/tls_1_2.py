#!/usr/bin/python3.5
# -*-coding:utf-8-*

""" Module which permit analysis of TLS1.2 protocol"""
import struct
from .utilities import *
from .client_hello import *
from .server_hello import *
from .certificate import *


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
