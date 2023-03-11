import socket
import sys

from ip_header import IP
from tcp_header import TCP

class Sniffer():
    def __init__(self):
        HOST = socket.gethostbyname(socket.gethostname())
        try:
            if sys.platform == 'win32':
                socket_prot = socket.IPPROTO_IP
            else:
                socket_prot = socket.IPPROTO_ICMP

            self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_prot)
            self.s.bind((HOST, 0))
            self.s.setblocking(False)

            if sys.platform == 'win32':
                self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except socket.error as msg :
            print(f"Socket couldn't be created. Error code: {msg.errno}\nMessage: {msg.strerror}")
            sys.exit()

    def start_sniffer(self):
        try:
            while True:
                try:
                    raw_data = self.s.recvfrom(65535)
                except socket.error as e:
                    if e.errno == 10035:
                        continue

                ip_header = IP(raw_data[0][:20])
                ip_header.display()

                if ip_header.protocol == 6:
                    tcp_header = TCP(raw_data[0][ip_header.length*4:ip_header.length*4+20])
                    tcp_header.display()

        except KeyboardInterrupt:
            if sys.platform == 'win32':
                self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self.s.close()
            sys.exit()
