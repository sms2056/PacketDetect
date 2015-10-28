import sys
import os
import struct
import io
import json

from constant import FileFormat
from module import pcap
from module import pcapng
import pcapng
import packet_parser


def GetFilePath(filespath):
    __object = filespath
    __files  = []
    if os.path.isdir(__object):
        for root, dirs, filenames in os.walk(__object):
            for name in filenames:
                __files.append(os.path.join(root, name))
    elif os.path.isfile(__object):
        __files.append(__object)
    else:
        print "You must supply a file or directory!"
        sys.exit()
    return __files

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

pcapdir_path = 'C:\XL_UDP'
pacpfile_list = GetFilePath(pcapdir_path)

client_ip = '192.168.1.86'
client_total_dict = {}
server_total_dict = {}
for pcapfile in pacpfile_list:
    client_pack_list = []
    server_pack_list = []
    infile = io.open(pcapfile,'rb')
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

    basename =os.path.basename(pcapfile)
    client_total_dict[basename] = client_pack_list
    server_total_dict[basename] = server_pack_list
    infile.close()

client_total_json = json.dumps(client_total_dict,indent=4)
server_total_json = json.dumps(server_total_dict,indent=4)
print 'client:\n',client_total_json
print 'server:\n',server_total_json
