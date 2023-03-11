import threading
import time

from sniffer import Sniffer

if __name__ == "__main__":
    s = Sniffer()
    s.start_sniffer()
    