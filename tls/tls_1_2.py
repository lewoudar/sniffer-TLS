""" Module which will permit analysis of TLS1.2 protocol"""
import struct
import textwrap
import binascii



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
		file.write(prefix + 'Handshake Type: {}, Handshake Length: {}\n'.format(handshake_type, handshake_length))

		# Client Hello
		if handshake_type == 1:
			handle_client_hello(file, prefix, data[9:])


# Returns properly formatted TLS version
def tls_version(version):
	bytes_str = map('{:02x}'.format, version)
	formatted_str = ''.join(bytes_str)
	if formatted_str == '0301':
		formatted_str = 'TLS1.0 - 0x' + formatted_str
	if formatted_str == '0302':
		formatted_str = 'TLS1.1 - 0x' + formatted_str
	if formatted_str == '0303':
		formatted_str = 'TLS1.2 - 0x' + formatted_str

	return formatted_str


def get_str_value(bytes_values):
	strings = [str(elt) for elt in bytes_values]
	return ''.join(strings)


def get_cipher_suite(bytes_suite):
	hex_value = binascii.hexlify(bytes_suite)
	return '0x' + hex_value.decode()


def handle_client_hello(file, prefix, data):
	max_tls_version, unix_time, random_value,\
		session_id_length, cipher_suites_length = struct.unpack('! 2s 4s 28s B 32x H', data[:69])

	file.write(prefix + 'Max TLS Version: {},'
						' Unix Time: {}\n'.format(tls_version(max_tls_version), get_str_value(unix_time)))
	file.write(prefix + 'Random Bytes: {}\n'.format(get_str_value(random_value)))
	file.write(prefix + 'Session Id length: {},'
						' Cipher Suites Length: {}\n'.format(session_id_length, cipher_suites_length))
	# Course all cryptographic suites
	if cipher_suites_length % 2 != 0:
		cipher_suites_length += 1
	search = '! ' + '2s' * (cipher_suites_length // 2)
	cipher_suites = struct.unpack(search, data[69: 69 + cipher_suites_length])
	for cipher in cipher_suites:
		file.write(prefix + 'Cipher Suite: {}\n'.format(get_cipher_suite(cipher)))
	# Compression method
	cursor = 69 + cipher_suites_length
	compression_method_length, compression_method = struct.unpack('! B B', data[cursor: cursor + 2])
	file.write(prefix + 'Compression Method Length: {}\n'.format(compression_method_length))
	file.write(prefix + 'Compression Method: {}\n'.format(compression_method))
	# Extensions
	cursor += 2
	extensions_length = struct.unpack('! H', data[cursor: cursor + 2])
	extensions_length = extensions_length[0]
	file.write(prefix + 'Extensions Length: {}\n'.format(extensions_length))
	cursor += 2
	extensions = data[cursor: cursor + extensions_length]

	# counter to browse the extension list
	i = 0
	while i < extensions_length:
		i += 2
		extension_type = extensions[cursor: cursor + i]
		extension_type = binascii.hexlify(extension_type)
		i += 2
		cursor += 2
		extension_length = extensions[cursor: cursor + i]
		file.write(prefix + 'len: {}'.format(len(extension_length)))
		extension_length = struct.unpack('! H', extension_length)[0]
		i += extension_length
		cursor += 2
		extension_value = extensions[cursor: cursor + extensions_length]
		cursor += extension_length
		i = 0
		file.write(prefix + 'Extension Type: {}\n'.format(extension_type))
		file.write(prefix + 'Extension Length: {}\n'.format(extension_length))
		file.write(prefix + 'Extension Value: {}\n'.format(extension_value))
		continue

	file.write(prefix + 'Data:\n')
	data_prefix = '\t' + prefix[:-3]
	file.write(format_multi_line(data_prefix, data))


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
	size -= len(prefix)
	if isinstance(string, bytes):
		string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
