import sys
import struct
import io

from constant import FileFormat
from module import pcap
import pcapng
import packet_parser

client_ip = '192.168.1.86'
client_pack_list = []
server_pack_list = []

def get_file_format(infile):
    """
    get cap file format by magic num.
    return file format and the first byte of string
    :type infile:file
    """
    buf = infile.read(4)
    if len(buf) == 0:
        # EOF
        print("empty file", sys.stderr)
        sys.exit(-1)
    if len(buf) < 4:
        print("file too small", sys.stderr)
        sys.exit(-1)
    magic_num, = struct.unpack(b'<I', buf)
    if magic_num == 0xA1B2C3D4 or magic_num == 0x4D3C2B1A:
        return FileFormat.PCAP, buf
    elif magic_num == 0x0A0D0D0A:
        return FileFormat.PCAP_NG, buf
    else:
        return FileFormat.UNKNOWN, buf

infile = io.open(r"c:\XL_UDP_7.9.40.5006_1.pcap",'rb')
file_format, head = get_file_format(infile)
if file_format == FileFormat.PCAP:
    pcap_file = pcap.PcapFile(infile, head).read_packet
elif file_format == FileFormat.PCAP_NG:
    pcap_file = pcapng.PcapngFile(infile, head).read_packet
else:
    print("unknown file format.", sys.stderr)
    sys.exit(1)

for udp_pac in packet_parser.read_udp_packet(pcap_file,20):
    if udp_pac.source == '192.168.1.86':
        client_pack_list.append(udp_pac.payload_len)
    if udp_pac.dest == '192.168.1.86':
        server_pack_list.append(udp_pac.payload_len)

print "client-->",client_pack_list
print "server-->",server_pack_list
infile.close()
