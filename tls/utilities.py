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
TAB_7 = '\t' + TAB_6

# Method which permit to read csv files and put
# data from it in a dictionnary called "dictionnary"
def read_csv_file(dictionnary, file_name):
	path = 'tls/parameters/' + file_name
	with open(path, newline='') as csvfile:
		values = csv.reader(csvfile, delimiter=',')
		for row in values:
			if file_name == "cipher-suites.csv":
				hexa_suite = row[0] # for example row[0] == "0xc0,0xc34"
				hexa_suite = hexa_suite.replace('0x', '')
				hexa_suite = hexa_suite.replace(',', '')
				hexa_suite = hexa_suite.lower()
				dictionnary[hexa_suite] = row[1]
			else:
				number = int(row[0])
				name = row[1]
				dictionnary[number] = name 


# We read the file which contains all cipher suites
# and filled it in a dictionnary crypto_suites
# which we use to identify all suites use in a negociation message
crypto_suites = {}
read_csv_file(crypto_suites, 'cipher-suites.csv')

# We read a file which contains all extensions values
# and filled it in a dictionnary extension_names
# which we use to identify all extensions names negociated
extension_names = {}
read_csv_file(extension_names, 'tls-extension-type-values.csv')


# We read a file which contains all certificate status
# and filled it in a dictionnary certificate_status_list
# which we use to identify the certificate status used by the client
certificate_status_list = {}
read_csv_file(certificate_status_list, 'certificate-status.csv')


# We read a file which contains all elliptic curves
# and filled it in a dictionnary supported_groups
# which we use to identify the elliptic curves used by the client
supported_groups = {}
read_csv_file(supported_groups, 'supported-groups.csv')


# We read a file which contains all EC point formats
# and filled it in a dictionnary ec_point_formats_list
# which we use to identify the EC point formats used by the client
ec_point_formats_list = {}
read_csv_file(ec_point_formats_list, 'ec-point-formats.csv')


# We read a file which contains all hash methods
# and filled it in a dictionnary hash_methods
# which we use to identify the hash methods used by the client
hash_methods = {}
read_csv_file(hash_methods, 'hash-algorithms.csv')


# We read a file which contains all signature methods
# and filled it in a dictionnary signature_methods
# which we use to identify the signature methods used by the client
signature_methods = {}
read_csv_file(signature_methods, 'signature-algorithms.csv')


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


def _handle_value(value, dictionnary, message):
	if value not in dictionnary:
		return '{} ({})'.format(message, value)

	return dictionnary[value] + ' ({})'.format(value)


def get_extension_type(value):
	return _handle_value(value, extension_names, 'unknow type')


def get_certificate_status(value):
	return _handle_value(value, certificate_status_list, 'unknow status')


def get_elliptic_curve(value):
	return _handle_value(value, supported_groups, 'unknow curve')


def get_ec_point_format(value):
	return _handle_value(value, ec_point_formats_list, 'unknow ec point format')


def get_hash_method(value):
	return _handle_value(value, hash_methods, 'unknow hash method')


def get_signature_method(value):
	return _handle_value(value, signature_methods, 'unknow signature method')

def get_extension_informations(file, data, extension_length, extension_type):
	file.write(TAB_5 + 'Extension Value:\n')

	if extension_type in extension_names:
		if extension_names[extension_type] == "status_request":
			get_status_request(file, data)
		elif extension_names[extension_type] == "server_name":
			get_server_name(file, data)
		elif extension_names[extension_type] == "renegotiation_info":
			get_renegotiation_info(file, data, extension_length)
		elif extension_names[extension_type] == "SessionTicket TLS":
			get_session_ticket_tls(file, data, extension_length)
		elif extension_names[extension_type] == 'supported_groups (renamed from "elliptic_curves")':
			get_supported_groups(file, data)
		elif extension_names[extension_type] == "ec_point_formats":
			get_ec_point_formats(file, data)
		elif extension_names[extension_type] == "signature_algorithms":
			get_signature_algorithms(file, data)
		elif extension_names[extension_type] == "application_layer_protocol_negotiation":
			get_alpn_infos(file, data)
		elif extension_names[extension_type] == "padding":
			get_padding_infos(file, data, extension_length)
		else:
			extension_value = struct.unpack('! ' + 's' * extension_length, data[:extension_length])
			file.write(TAB_6 +  '{}\n'.format(extension_value))
			
	else:
		extension_value = struct.unpack('! ' + 's' * extension_length, data[:extension_length])
		file.write(TAB_6 +  '{}\n'.format(extension_value))


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
	size -= len(prefix)
	if isinstance(string, bytes):
		string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

######### EXTENSIONS INFORMATIONS ########

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


def get_renegotiation_info(file, data, extension_length):
	info_ext_length = struct.unpack('! B', data[:1])[0]
	file.write(TAB_6 + 'Renegotiation Info Extension Length: {}\n'.format(info_ext_length))


def get_session_ticket_tls(file, data, extension_length):
	session_ticket_data = struct.unpack('! ' + 's' * extension_length, data[:extension_length])
	if len(session_ticket_data) > 0:
		file.write(TAB_6 + 'Data :{}\n'.format(get_string(session_ticket_data)))
	else:
		file.write(TAB_6 + 'Data : None (0 byte)\n')


def get_supported_groups(file, data):
	elliptic_curve_length = struct.unpack('! H', data[:2])[0]

	for i in range(0, elliptic_curve_length // 2):
		elliptic_curve = struct.unpack('! H', data[2 + 2 * i : 2 + 2 * (i + 1)])[0]
		file.write(TAB_6 + 'Elliptic Curve: {}\n'.format(get_elliptic_curve(elliptic_curve)))


def get_ec_point_formats(file, data):
	ec_point_format_length = struct.unpack('! B', data[:1])[0]
	ec_point_format = struct.unpack('! B', data[1:2])[0]
	file.write(TAB_6 + 'EC Point Formats Length: {}\n'.format(ec_point_format_length))
	file.write(TAB_6 + 'EC Point Format: {}\n'.format(get_ec_point_format(ec_point_format)))


def get_signature_algorithms(file, data):
	hash_algorithms_length = struct.unpack('! H', data[:2])[0]

	for i in range(0, hash_algorithms_length // 2):
		hash_method, signature_method = struct.unpack('! B B', data[2 + 2 * i : 2 + 2 * (i + 1)])
		file.write(TAB_6 + 'Signature Hash algorithm: {} - {}\n'.format( \
			get_hash_method(hash_method), get_signature_method(signature_method)))


def get_alpn_infos(file, data):
	alpn_extension_length = struct.unpack('! H', data[:2])[0]
	file.write(TAB_6 + 'ALPN Extension Length: {}\n'.format(alpn_extension_length))
	# we remove data containing ALPN protocols into a a variable
	alpn_data = data[2:]
	# cursor is used to browse all ALPN protocols
	cursor = 0
	while cursor < alpn_extension_length:
		alpn_string_length = struct.unpack('! B', alpn_data[cursor : cursor + 1])[0]
		cursor += 1
		alpn_protocol = struct.unpack('! ' + 's' * alpn_string_length, alpn_data[cursor :cursor + alpn_string_length])
		file.write(TAB_7 + 'ALPN String Length: {}\n'.format(alpn_string_length))
		file.write(TAB_7 + 'ALPN Protocol: {}\n'.format(get_string(alpn_protocol)))
		cursor += alpn_string_length


def get_padding_infos(file, data, extension_length):
	padding = struct.unpack('! ' + 's' * extension_length, data[:extension_length])
	file.write(TAB_6 + 'Padding: {}\n'.format(get_number(padding)))

