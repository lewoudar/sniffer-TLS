#!/usr/bin/python3.5
# -*-coding:utf-8 -*
import struct
from .utilities import *

"""Module which handle client hello handshake protocol for TLS1.2"""

def handle_client_hello(file, prefix, data):
	max_tls_version, unix_time, random_value,\
		session_id_length, cipher_suites_length = struct.unpack('! 2s 4s 28s B H', data[:37])

	file.write(prefix + 'Max TLS Version: {},'
						' Unix Time: {}\n'.format(tls_version(max_tls_version), get_str_value(unix_time)))
	file.write(prefix + 'Random Bytes: {}\n'.format(get_str_value(random_value)))
	file.write(prefix + 'Session Id length: {},'
						' Cipher Suites Length: {}\n'.format(session_id_length, cipher_suites_length))
	
	file.write(format_multi_line(TAB_3, data))