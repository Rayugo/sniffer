from struct import unpack
from socket import inet_ntoa

class IP:
    def __init__(self, packet):
        header = unpack("!BBHHHBBH4s4s", packet)
        self.version = header[0] >> 4
        self.length = header[0] & 0x0F
        self.dscp = header[1] >> 2 #Differentiated Services Code Point 
        self.ecn = header[1] & 0x03 #Explicit Congestion Notification
        self.total_length = header[2]
        self.identification = header[3]
        self.flags = header[4] & 0xE000
        self.fragment_offset = header[4] & 0x1FFF
        self.ttl = header[5]
        self.protocol = header[6]
        self.checksum = header[7]
        self.source_ip = inet_ntoa(header[8])
        self.dest_ip = inet_ntoa(header[9])

        self.protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
        }
    
    def display(self):
        try:
            p = self.protocol_map[self.protocol]
            print(f"{p}: {self.source_ip}->{self.dest_ip}")
        except Exception as e:
            print("Couldn't identify the protocol: ")
            print(f"{self.source_ip}->{self.dest_ip}")