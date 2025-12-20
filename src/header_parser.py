import string
import struct
import socket
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

class HeaderParser:
    @staticmethod
    def parse_ethernet(packet, offset=0):
        eth_len = 14
        if len(packet) < offset + eth_len:
            return None

        dst, src, protocol = struct.unpack(
            "!6s6sH", packet[:eth_len]
        )

        return {
            "src_mac": ":".join(f"{b:02x}" for b in src),
            "dst_mac": ":".join(f"{b:02x}" for b in dst),
            "protocol": protocol,
            "offset": offset + 14
        }

    @staticmethod
    def parse_ip(packet, offset):
        # Minimum: protocol byte must exist
        if len(packet) < offset + 10:
            return None

        ver_ihl = packet[offset]
        ihl = (ver_ihl & 0x0F) * 4
        if ihl < 20:
            ihl = 20

        proto = packet[offset + 9]

        src = packet[offset + 12 : offset + 16]
        dst = packet[offset + 16 : offset + 20]

        return {
            "src_ip": socket.inet_ntoa(src) if len(src) == 4 else "",
            "dst_ip": socket.inet_ntoa(dst) if len(dst) == 4 else "",
            "ttl": packet[offset + 8] if len(packet) > offset + 8 else None,
            "protocol": proto,
            "offset": offset + ihl
        }

    @staticmethod
    def parse_tcp(packet, offset):
        if len(packet) < offset + 4:
            return None

        src_port = struct.unpack(">H", packet[offset: offset + 2])[0]
        dst_port = struct.unpack(">H", packet[offset + 2: offset + 4])[0]

        if len(packet) >= offset + 13:
            data_offset = (packet[offset + 12] >> 4) * 4
            if data_offset < 20:
                data_offset = 20
        else:
            data_offset = 20

        payload_offset = offset + data_offset
        payload_bytes = packet[payload_offset:]

        is_http = src_port == 80 or dst_port == 80

        if is_http:
            logger.warning("is HTTP!!")
            try:
                payload = payload_bytes.decode("utf-8", errors="ignore")
                payload = "".join(
                    c if c in string.printable else "." for c in payload
                )
            except:
                payload = "<Binary>"
        else:
            payload = ""

        logger.warning("raw payload: %s", payload_bytes)
        logger.warning("processed payload: %s", payload)

        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "payload": payload,
            "is_http": is_http,
        }

    @staticmethod
    def parse_udp(packet, offset):
        if len(packet) < offset + 4:
            return None

        src_port = struct.unpack(">H", packet[offset : offset + 2])[0]
        dst_port = struct.unpack(">H", packet[offset + 2 : offset + 4])[0]

        return {
            "src_port": src_port,
            "dst_port": dst_port
        }
