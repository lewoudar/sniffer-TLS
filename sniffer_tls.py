#!/usr/bin/python3.5
# -*-coding:utf-8 -*

import socket
import struct
import os
import tls.tls_1_2 as tls

# Delete the old TLS capture file if exists
if os.path.exists('tls_tcp_output.txt'):
    os.system('rm tls_tcp_output.txt')

# Constants for pretty print
DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '
TAB_1 = DATA_TAB_1 + '- '
TAB_2 = DATA_TAB_2 + '- '
TAB_3 = DATA_TAB_3 + '- '
TAB_4 = DATA_TAB_4 + '- '


# Main function
def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = connection.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        # 8 for IPV4
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(TAB_1 + 'IPV4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # TCP
            if proto == 6:
                src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, \
                    flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(seq, ack))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {},'
                              ' FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(tls.format_multi_line(DATA_TAB_3, data))

                # If it is TLS, save output in file
                if (dest_port == 443 or src_port == 443) and len(data) > 5:
                    save_in_file(dest_mac, src_mac, eth_proto,
                                 version, header_length, ttl, proto, src, target,
                                 src_port, dest_port, seq, ack, flag_urg, flag_ack,
                                 flag_psh, flag_rst, flag_syn, flag_fin,
                                 data, 'tls_tcp_output.txt')

            # UDP
            if proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Length: {}'.format(length))
                print(TAB_2 + 'Data:')
                print(tls.format_multi_line(DATA_TAB_3, data))


# Unpacks ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# Return properly formatted MAC address (i.e AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


# Unpacks IPV4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# Returns properly formatted IPV4 address
def ipv4(addr):
    return ':'.join(map(str, addr))


# Unpacks TCP segment
def tcp_segment(data):
    src_port, dest_port, sequence, ack, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# Unpacks UDP segment
def udp_segment(data):
    src_port, dst_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dst_port, size, data[8:]


def save_in_file(dest_mac, src_mac, eth_proto,
                 ip_version, header_length, ttl, proto, src, target,
                 src_port, dest_port, seq, ack, flag_urg, flag_ack,
                 flag_psh, flag_rst, flag_syn, flag_fin,
                 data, file_name):

    # Writing in file 'file_name'
    with open(file_name, 'a') as file:
        # Ethernet part
        file.write('\nEthernet frame:\n')
        file.write(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}\n'.format(dest_mac, src_mac, eth_proto))
        # IP part
        file.write(TAB_1 + 'IPV4 Packet:\n')
        file.write(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}\n'.format(ip_version, header_length, ttl))
        file.write(TAB_2 + 'Protocol: {}, Source: {}, Target: {}\n'.format(proto, src, target))
        # TCP part
        file.write(TAB_1 + 'TCP Segment:\n')
        file.write(TAB_2 + 'Source Port: {}, Destination Port: {}\n'.format(src_port, dest_port))
        file.write(TAB_2 + 'Sequence: {}, Acknowledgement: {}\n'.format(seq, ack))
        file.write(TAB_2 + 'Flags:\n')
        file.write(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {},'
                           ' SYN: {},FIN: {}\n'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
        # TLS dissection
        tls.tls_packet(file, TAB_3, data)

        # Jump a line
        file.write('\n')


if __name__ == "__main__":
    main()
