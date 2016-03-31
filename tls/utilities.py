"""Module which contains functions to print TLS parameters"""
import struct
import binascii
import textwrap
import csv

# Constants for pretty print
DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '
DATA_TAB_5 = '\t\t\t\t\t '
TAB_1 = DATA_TAB_1 + '- '
TAB_2 = DATA_TAB_2 + '- '
TAB_3 = DATA_TAB_3 + '- '
TAB_4 = DATA_TAB_4 + '- '
TAB_5 = DATA_TAB_5 + '- '

# We read the file which contains all cipher suites
# and filled it in a dictionnary crypto_suites
# which we use to identify all suites use in a negociation message
crypto_suites = {}
with open('tls/parameters/cipher-suites.csv') as csvfile:
	tls_suites = csv.reader(csvfile, delimiter=',')
	for row in tls_suites:
		hexa_suite = row[0] # for example row[0] == "0xc0,0xc34"
		hexa_suite = hexa_suite.replace('0x', '')
		hexa_suite = hexa_suite.replace(',', '')
		hexa_suite = hexa_suite.lower()
		crypto_suites[hexa_suite] = row[1]

# We read a file which contains all extensions values
# and filled it in a dictionnary extension_names
# which we use to identify all extensions names
extension_names = {}
with open('tls/parameters/tls-extension-type-values.csv', newline='') as csvfile:
	extensions = csv.reader(csvfile, delimiter=',')
	for row in extensions:
		number = int(row[0])
		name = row[1]
		extension_names[number] = name

# Returns properly formatted TLS version
def tls_version(version):
	bytes_str = map('{:02x}'.format, version)
	formatted_str = ''.join(bytes_str)

	if formatted_str == '0301':
		formatted_str = 'TLS1.0 (0x' + formatted_str + ')'
	if formatted_str == '0302':
		formatted_str = 'TLS1.1 (0x' + formatted_str + ')'
	if formatted_str == '0303':
		formatted_str = 'TLS1.2 (0x' + formatted_str + ')'

	return formatted_str


def get_str_value(bytes_values):
	strings = [str(elt) for elt in bytes_values]
	return ''.join(strings)


def get_cipher_suite(bytes_suite):
	hex_value = binascii.hexlify(bytes_suite)
	if hex_value.decode() in crypto_suites:
		return crypto_suites[hex_value.decode()] + ' (0x{})'.format(hex_value.decode())

	return '0x' + hex_value.decode()


def get_extension_type(value):
	if value in extension_names:
		return extension_names[value] + ' ({})'.format(value)

	return '{} unknow type'.format(value)


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
	size -= len(prefix)
	if isinstance(string, bytes):
		string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])