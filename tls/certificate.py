#!/usr/bin/python3.5
# -*-coding:utf-8 -*
import struct
from .utilities import *

"""Module which handle certificate handshake protocol for TLS1.2"""

def handle_certificate(file, prefix, data):
	# cursor: variable to browse all TLS data
	cursor = 4
	# Certificates length
	certificates_length = struct.unpack('! I', data[:cursor])[0]
	certificates_length >>= 8
	file.write(prefix + 'Certificates Length: {}\n'.format(certificates_length))
	# Browse all certificates
	cert_data = data[3 : certificates_length]
	cursor = 0
	while cursor < certificates_length:
		certificate_length = struct.unpack('! I', cert_data[:cursor + 4])[0]
		certificate_length >>= 8
		cursor += 3
		certificate = struct.unpack('! ' + 's' * certificate_length, cert_data[cursor:cursor + certificate_length])
		cursor += certificate_length
		file.write(TAB_5 + 'Certificate Length: {}\n'.format(certificate_length))
		file.write(TAB_5 + 'Certificate: {}\n'.format(get_string(certificate)))