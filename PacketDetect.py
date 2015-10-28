__author__ = 'sms2056'

import io
import os
import time

from optparse import OptionParser
from module.base import GetFilePath, CheckIP, GetFileFormat, MD5SUM
from module import pcap
from module import pcapng
from module.constant import FileFormat
from module.packet_parser import Read_Packet
from module.syslog import syslog,GetCurrentLine

logger = syslog(module_name="PacketDetect")


if __name__ == '__main__':
    parser = OptionParser(usage="%prog -p d:\code\PFI\XL_UDP -H 192.168.1.86 -e\n by sms2056", version="%prog 0.1")
    parser.add_option("-p", "--path", type='str', dest="pkt_path", default='NULL', help="pcap file path")
    parser.add_option("-e", "--extract", action="store_true", dest="pkt_extract", help="DFI Feature extraction")
    parser.add_option("-H", "--host", type='str', dest="pkt_host", default='0.0.0.0', help="Local Host IP or Client IP or Intranet IP")
    parser.add_option("-n", "--count", type='int', dest="pkt_count", default=20, help="Browse data size")
    # parser.add_option("-s", "--single", action="store_true", dest="pkt_single", help="single packet detect")
    # parser.add_option("-m", "--multiple", action='store_true', dest="pkt_multiple", help="multiple detect")
    #parser.add_option("-P", "--dpi", type = 'int', dest="pkt_dpi", default=7200, help="Start time")
    #parser.add_option("-F", "--dfi", type='int', dest="pkt_dfi_time", default=7200, help="Start time")

    (options, args) = parser.parse_args()
    if args !=[]:
        print("Error: %s option requires an argument" % args)
        exit()

    # if options.pkt_single == None and options.pkt_multiple == None:
    #     logger.ShowLog("-s,-m One of them must be set.", GetCurrentLine())
    #     exit()
    #
    # if options.pkt_single == True and options.pkt_multiple == True:
    #     logger.ShowLog("-s,-m Can not be set at the same time.", GetCurrentLine())
    #     exit()

    if CheckIP(options.pkt_host) == False:
        exit()
    elif options.pkt_host == '0.0.0.0':
        logger.ShowLog("IP = 0.0.0.0,Please enter the correct value", GetCurrentLine(), 2)

    if options.pkt_path == 'NULL':
        logger.ShowLog("pcap file path is null", GetCurrentLine())
        exit()

    pktfile_list = GetFilePath(options.pkt_path)
    pktfile_list_size = len(pktfile_list)
    information = "load packet file %s" % pktfile_list_size
    logger.ShowLog(information, GetCurrentLine(), 1)

    if options.pkt_extract == True:
        client_total_dict = {}
        server_total_dict = {}
        for pktfile in pktfile_list:
            client_pack_list = []
            server_pack_list = []
            infile = io.open(pktfile,'rb')
            file_format, head = GetFileFormat(infile)
            if file_format == FileFormat.PCAP:
                packet_file = pcap.PcapFile(infile, head).read_packet
            elif file_format == FileFormat.PCAP_NG:
                packet_file = pcapng.PcapngFile(infile, head).read_packet
            else:
               logger.ShowLog("unknown file format.Unknown file type", GetCurrentLine())
               exit(1)

            pkt_ip_counter=set()
            pkt_depth_counter = 0
            for packet in Read_Packet(packet_file, options.pkt_count):
                if pkt_depth_counter == options.pkt_count:
                    break

                pkt_ip_counter.add(packet.source)
                pkt_ip_counter.add(packet.dest)
                if len(pkt_ip_counter) > 2:
                    msg = 'Only a single session flow is supported:%s file Existing problems' % pktfile
                    logger.ShowLog(msg)
                    exit()

                if packet.source == options.pkt_host:
                    if len(client_pack_list) <= 9:
                        client_pack_list.append(packet.payload_len)
                if packet.dest == options.pkt_host:
                    if len(server_pack_list) <= 9:
                        server_pack_list.append(packet.payload_len)
                pkt_depth_counter = pkt_depth_counter + 1

            pkt_basename =os.path.basename(pktfile)
            client_total_dict[pkt_basename] = client_pack_list
            server_total_dict[pkt_basename] = server_pack_list
            infile.close()

        tempfilename = "%s\\sms2056_PacketDetect_%s.txt" % (os.environ["TMP"], time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime(time.time())))
        tmpfile_handle = open(tempfilename, 'w')

        for packetname,lens in client_total_dict.items():
            tmpfile_handle.writelines("%s --> %s\n" % (packetname,MD5SUM(packetname)))

        tmpfile_handle.writelines("*****************************************************************\n")
        print('{client_total_dict}')
        tmpfile_handle.write('{client_total_dict}\n')
        for packetname,lens in client_total_dict.items():
            print(packetname+"\t"),
            tmpfile_handle.write(MD5SUM(packetname)+"\t")
            for x in lens:
                print("%d\t" % x),
                tmpfile_handle.writelines("%d\t" % x)
            print("")
            tmpfile_handle.writelines('\n')

        print('\n\n{server_total_dict}')
        tmpfile_handle.write('\n\n{server_total_dict}\n')
        for packetname,lens in server_total_dict.items():
            print(packetname+"\t"),
            tmpfile_handle.write(MD5SUM(packetname)+"\t")
            for x in lens:
                print ("%d\t" % x),
                tmpfile_handle.writelines("%d\t" % x)
            print("")
            tmpfile_handle.writelines('\n')

        tmpfile_handle.close()