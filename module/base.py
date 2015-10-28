__author__ = 'sms2056'
import os
import sys
import struct
import hashlib

from module.syslog import syslog,GetCurrentLine
logger = syslog(module_name="base")

from module.constant import FileFormat

def GetFilePath(filespath):
    if filespath[0] == '\'' or filespath[-1] == '\'':
        print(" include (\'),(\'\') at str[0],str[-1] Error")
        return False

    __object = filespath
    __files = []
    if os.path.isdir(__object):
        for root, dirs, filenames in os.walk(__object):
            for name in filenames:
                __files.append(os.path.join(root, name))
    elif os.path.isfile(__object):
        __files.append(__object)
    else:
        print("not find file or directory!")
        return False
    return __files

def GetFileFormat(infile):
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

def CheckIP(ipadress):
    if isinstance(ipadress, str) == False:
        logger.ShowLog("ip is str type", GetCurrentLine())
        return False

    ip_port_list = ipadress.split(':')
    ip_split = ip_port_list[0].split('.')

    if len(ip_split) != 4:
        logger.ShowLog("not ip address", GetCurrentLine())
        return False

    if ':' in ipadress:
        if ip_port_list[1].isdigit() == False:
            logger.ShowLog("not ip address", GetCurrentLine())
            return False

    for ip in ip_split:
        if ip.isdigit() == False:
            logger.ShowLog("not ip address", GetCurrentLine())
            return False
        if int(ip) > 255 or int(ip) < 0:
            logger.ShowLog("not ip address", GetCurrentLine())
            return False
    return True

def MD5SUM(value):
    m = hashlib.md5(value.encode('utf-8'))
    return m.hexdigest()