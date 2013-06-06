################################################################################
## poisonivyscan.py
##
## Poison Ivy Client RAT scanner written by Xiobe 
################################################################################
## This script is based on the following information:
## http://www.malware.lu/Pro/RAP002_APT1_Technical_backstage.1.0.pdf
## http://badishi.com/initial-analysis-of-poison-ivy/
## http://badishi.com/own-and-you-shall-be-owned/
################################################################################

import argparse
import iptools
import re
import socket

OPTION_SCRIPT_DESC = "Scanner To Detect Poison Ivy RAT"
OPTION_IP_DESC = "IP address to scan"
OPTION_FILE_DESC = "IP list to scan, syntax is 1 IP per line IP[:port]"
OPTION_PORT_DESC = "The default port is TCP 3460"
OPTION_RANGE_DESC = "The IP range to scan, CIDR syntax x.x.x.x/y"

DETECTION_MSG = " has Poison Ivy client running on "
NODETECTION_MSG = " has no Poison Ivy client running on "

def iplistgenerator(range):
   for ip in iptools.IpRangeList(range):
       scan(ip)

def iplistscan(file):
   filehandler = open(file)
   for line in filehandler:
        if "#" not in line:
            if ":" in line:
                (ip,port) = line.strip().split(':')
                scan(ip,int(port))
            else:
                scan(line.strip())

def scan(ip,port=3460):
    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientsocket.settimeout(6)
    try:
        clientsocket.connect((ip,port))
        # The client sends 256 bytes of pseudo-random data
        triggerdata = "\x00" * 0x100
        clientsocket.sendall(triggerdata)
        answerdata = clientsocket.recv(0x100)
        if len(answerdata) != 0x100:
            clientsocket.close()
            return
        else:
            data = clientsocket.recv(0x4)
            clientsocket.close()

        if data != "\xD0\x15\x00\x00":
             return
        else:
             print "%s" + DETECTION_MSG + "%d" % (ip, port)

    except socket.timeout as e:
        print "%s" + NODETECTION_MSG + "%d" % (ip, port)
    except socket.error as e:
        pass

def main():
    try:
        parser = argparse.ArgumentParser(description = OPTION_SCRIPT_DESC)
        parser.add_argument('--ip', help=OPTION_IP_DESC)
        parser.add_argument('--file', help=OPTION_FILE_DESC)
        parser.add_argument('--port', help=OPTION_PORT_DESC)
        parser.add_argument('--range', help=OPTION_RANGE_DESC)
        args = parser.parse_args()
        if (args.ip != None) and (args.file == None) and (args.range == None):
             if args.port:
                  scan(args.ip,int(args.port))
             else:
                  scan(args.ip)
        if (args.ip == None) and (args.file != None) and (args.range == None):
             iplistscan(args.file)
        if (args.ip == None) and (args.file == None) and (args.range == None):
             if args.port:
                 scan(socket.gethostbyname(socket.gethostname()),int(args.port))
             else:
                 scan(socket.gethostbyname(socket.gethostname()))
        if (args.ip == None) and (args.file == None) and (args.range != None):
            iplistgenerator(args.range)
        if (args.ip != None) and (args.file != None) and (args.range != None):
             print "Multiple arguments are not acceptable."
    except (KeyboardInterrupt, SystemExit):
        pass
 
if __name__ == '__main__':
   main()
