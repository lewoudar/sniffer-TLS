"""Module which contains functions to print TLS parameters"""
import struct
import binascii
import textwrap

# Constants for pretty print
DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '
TAB_1 = DATA_TAB_1 + '- '
TAB_2 = DATA_TAB_2 + '- '
TAB_3 = DATA_TAB_3 + '- '
TAB_4 = DATA_TAB_4 + '- '


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


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
	size -= len(prefix)
	if isinstance(string, bytes):
		string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])