from struct import unpack

class TCP:
    def __init__(self, segment):
        header = unpack("!HHIIBBHHH", segment)
        self.src_port = header[0]
        self.dst_port = header[1]
        self.seq_num = header[2]
        self.ack_num = header[3]
    
    def display(self):
        print(f"SRC {self.src_port} -> DST {self.dst_port}\n")