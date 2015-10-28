__author__ = 'sms2056'
import logging
import os
import sys
import time

tempfilename = "%s\\sms2056_PacketDetect_%s.log" % (os.environ["TMP"], time.strftime('%Y-%m-%d',time.localtime(time.time())))

CRITICAL = 50
FATAL = CRITICAL
ERROR = 40
WARNING = 30
WARN = WARNING
INFO = 20
DEBUG = 10
NOTSET = 0

def GetCurrentLine():
    """Return the frame object for the caller's stack frame."""
    try:
        raise Exception
    except:
        f = sys.exc_info()[2].tb_frame.f_back
    return str(f.f_lineno)


class syslog:
    def __init__(self, module_name, loglevel = DEBUG):
        self.__syslog = logging.getLogger(module_name)
        self.__syslog.setLevel(loglevel)
        self.__syslog_format = logging.Formatter('[*]%(asctime)s [%(name)s] %(levelname)s :  %(message)s', '%a, %d %b %Y %H:%M:%S')

        self.__logfile_handler = logging.FileHandler(tempfilename)
        self.__logfile_handler.setFormatter(self.__syslog_format)

        self.__logstream_handler = logging.StreamHandler(sys.stderr)
        self.__logstream_handler.setFormatter(self.__syslog_format)

        self.__syslog.addHandler(self.__logfile_handler)
        self.__syslog.addHandler(self.__logstream_handler)

    def ShowLog(self, log_Content='', currentline = 0, loglevel = 3):
        Content = log_Content + ' --> [+]LINE:%s' % currentline
        if loglevel == 1:
             self.__syslog.info(Content)
        elif loglevel == 2:
             self.__syslog.warning(Content)
        elif loglevel == 3:
             self.__syslog.error(Content)
        elif loglevel == 0:
             self.__syslog.debug(Content)
