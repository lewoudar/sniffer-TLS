#!/usr/bin/python3.5
# -*-coding:utf-8 -*
import struct
from .utilities import *

"""Module which handle new session ticket handshake protocol for TLS1.2"""

def handle_new_session_ticket(file, prefix, data):
	# cursor: variable to browse all TLS data
	cursor = 4
	# Session Ticket Lifetime Hint
	lifetime_hint = struct.unpack('! I', data[:cursor])[0]
	file.write(prefix + 'Session Ticket Lifetime Hint: {}\n'.format(lifetime_hint))
	# Session ticket Length
	session_ticket_length = struct.unpack('! H', data[cursor : cursor + 2])[0]
	file.write(prefix + 'Session Ticket Length: {}\n'.format(session_ticket_length))
	# Session Ticket
	cursor += 2
	session_ticket = str(binascii.hexlify(data[cursor : cursor + session_ticket_length]))[2:-1]
	file.write(prefix + 'Session Ticket: {}\n'.format(session_ticket))
