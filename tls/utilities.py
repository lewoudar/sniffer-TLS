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
TAB_6 = '\t' + TAB_5

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
# which we use to identify all extensions names negociated
extension_names = {}
with open('tls/parameters/tls-extension-type-values.csv', newline='') as csvfile:
	extensions = csv.reader(csvfile, delimiter=',')
	for row in extensions:
		number = int(row[0])
		name = row[1]
		extension_names[number] = name


# We read a file which contains all certificate status
# and filled it in a dictionnary certificate_status_list
# which we use to identify the certificate status used by the client
certificate_status_list = {}
with open('tls/parameters/certificate-status.csv', newline='') as csvfile:
	status = csv.reader(csvfile, delimiter=',')
	for row in status:
		number = int(row[0])
		name = row[1]
		certificate_status_list[number] = name


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


def get_number(bytes_values):
	strings = [str(elt) for elt in bytes_values]
	return ''.join(strings)


def get_string(bytes_values):
	# Each byte character x is like this 'bx' when converted to str
	# I remove what is unnecessary
	strings = [str(elt)[2:-1] for elt in bytes_values]
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

def get_certificate_status(value):
	if value in certificate_status_list:
		return certificate_status_list[value] + ' ({})'.format(value)

	return '{} unknow status'.format(value)


def get_extension_informations(file, data, extension_length, extension_type):
	file.write(TAB_5 + 'Extension Value:\n')

	if extension_type in extension_names:
		if extension_names[extension_type] == "status_request":
			get_status_request(file, data)
		if extension_names[extension_type] == "server_name":
			get_server_name(file, data)
		if extension_names[extension_type] == "renegotiation_info":
			get_renegotiation_info(file, data)
			
	else:
		extension_value = struct.unpack('! ' + 's' * extension_length, data[extension_length])
		file.write(TAB_6 +  '{}\n'.format(extension_value))


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
	size -= len(prefix)
	if isinstance(string, bytes):
		string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def get_status_request(file, data):
	certificate_status_type = struct.unpack('! B', data[:1])[0]
	certificate_status_type = get_certificate_status(certificate_status_type)
	responder_id_list_length = struct.unpack('! H', data[1:3])[0]
	request_extensions_length = struct.unpack('! H', data[3:])[0]
	file.write(TAB_6 + 'Certificate Status Type: {}\n'.format(certificate_status_type))
	file.write(TAB_6 + 'Responder ID List Length: {}\n'.format(responder_id_list_length))
	file.write(TAB_6 + 'Request Extensions Length: {}\n'.format(request_extensions_length))


def get_server_name(file, data):
	server_name_list_length = struct.unpack('! H', data[:2])[0]
	server_name_type = struct.unpack('! B', data[2:3])[0]
	server_name_length = struct.unpack('! H', data[3:5])[0]
	server_name = struct.unpack('! ' + 's' * server_name_length, data[5 : 5 + server_name_length])
	file.write(TAB_6 + 'Server Name List Length: {}\n'.format(server_name_list_length))
	file.write(TAB_6 + 'Server Name Type: {}\n'.format(server_name_type))
	file.write(TAB_6 + 'Server Name Length: {}\n'.format(server_name_length))
	file.write(TAB_6 + 'Server Name: {}\n'.format(get_string(server_name)))


def get_renegotiation_info(file, data):
	info_ext_length = struct.unpack('! B', data[:1])
	file.write(TAB_6 + 'Renegotiation Info Extension Length: {}\n'.format(info_ext_length))