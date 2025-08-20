from scapy.utils import PcapWriter

class PacketPcapSaver:
    def __init__(self, filename):
        # append=False means naya file banega, exist karta ho to overwrite
        self.writer = PcapWriter(filename, append=False, sync=True)

    def write_packet(self, packet):
        self.writer.write(packet)

    def close(self):
        self.writer.close()
