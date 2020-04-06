# Ali Abdollahi - This tool designed to capture IP packets

import socket
import struct
import sys

def dissect(packet):
    ip_header = struct.unpack("!12s4s4s",packet)
    print("Source Address: ", socket.inet_ntoa(ip_header[1]), " --> ","Destination Address: ", socket.inet_ntoa(ip_header[2]))
    
    
def linux():
    print("Linux Detected")
    eth = input("Insert the Interface that You Want to Sniff On: ")
    sniffer = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))
    sniffer.bind((eth,0))
    while True:
        buffer = sniffer.recvfrom(2048)
        buffer = buffer[0][14:34]
        dissect(buffer)
    sniffer.close()

def windows():
    print("Windows Detected")
    host = input("Insert the IP Address that You Want to Sniff On: ")
    sniffer = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
    sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    sniffer.bind((host,0))
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    while True:
        pkt = sniffer.recvfrom(2048)
        pkt = pkt[0][0:20]
        dissect(pkt)
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    sniffer.close()

def main():
    if sys.platform == "win32":
        windows()
    elif sys.platform == "linux":
        linux()
    else:
        print("Not Spuported Platform")
        sys.exit()

if __name__ == '__main__':
    main()
    