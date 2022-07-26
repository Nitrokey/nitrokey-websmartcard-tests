import socket


class HidOverUDP:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 7112))
        addr, port = path.split(":")
        port = int(port)
        self.token = (addr, port)
        self.sock.settimeout(1.0)

    def Write(self, packet):
        self.sock.sendto(bytearray(packet), self.token)

    def Read(self):
        pkt, _ = self.sock.recvfrom(73)
        return pkt
