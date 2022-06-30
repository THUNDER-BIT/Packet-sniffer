import socket
import struct
import textwrap


# main program is a big infinite loop that will keep on listening to packets
def main():
    connect = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = connect.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print("\nEthernet Frame")
        print("Destination: {}, Source: {} , Protocol: {}".format(dest_mac, src_mac, eth_proto))

        if eth_proto == 8:  # 8 is for IPv4 normal intenet traffic
            version, header_length, ttl, proto, src, target, data = IPv4_packet(data)
            print("IPv4 Packet")
            print("Version: {}, Header Length: {}, TTL: {}".format(version, header_length, ttl))
            print("Protocal: {}, source: {}, Target: {}".format(proto, src, target))

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print("ICMP packet:")


            elif proto == 6:
                print("TCP Packet:")

            elif proto == 17:
                print("UDP Segment")

            else:
                print("Data:")
        else:
            print("Data:")


# unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    # the ! is for specifying that data os network big indian n little indian
    return get_mac_addr(src_mac), get_mac_addr(dest_mac), socket.htons(proto), data[14:]


# returns proper format for mac_addr( aa:bb:cc:dd:ee)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


# unpacks IPv4 packets
def IPv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, IPv4(src), IPv4(target), data[header_length:]


# returns properly formatted IPv4 addr
def IPv4(addr):
    return ':'.join(map(str, addr))


# unpack icmp packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# unpack tcp packet
def tcp_segment(data):
    (src_port, dest_port, seq, ack, offset_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_flags >> 12) * 4
    flag_urg = (offset_flags & 32) * 5
    flag_ack = (offset_flags & 16) * 4
    flag_psh = (offset_flags & 8) * 3
    flag_rst = (offset_flags & 4) * 2
    flag_syn = (offset_flags & 2) * 1
    flag_fin = (offset_flags & 2)
    return src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# unpack udp packet
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[0:]


# format multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ' '.join(r'\x[:02x]'.format(byte) for byte in string)
        if size % 2:
            size -= 1

    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
