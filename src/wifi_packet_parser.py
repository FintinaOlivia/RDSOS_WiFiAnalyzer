import struct
import time
from collections import defaultdict

class WiFiPacketParser:
    @staticmethod
    def parse_radiotap(packet):
        try:
            if len(packet) < 4:
                return -100, 0  

            radiotap_len = struct.unpack_from("<H", packet, 2)[0]

            if len(packet) < radiotap_len:
                return -100, radiotap_len

            rssi = -100

            scan_end = min(radiotap_len, len(packet))
            for i in range(scan_end - 1, 8, -1):
                try:
                    byte_val = struct.unpack("b", packet[i : i + 1])[0]
                    if -95 <= byte_val <= -10:
                        rssi = byte_val
                        break
                except:
                    continue

            return rssi, radiotap_len

        except Exception as ex:
            return -100, 24 


    @staticmethod
    def parse_80211_header(packet, radiotap_len):
        header_length = 24

        if len(packet) < radiotap_len + header_length:
            return None, None, None

        dot11_header = packet[radiotap_len : radiotap_len + header_length]

        # Frame Control field (2 bytes)
        fc, = struct.unpack_from("<H", dot11_header, 0)
        frame_type = (fc >> 2) & 0b11        # bits 2-3
        frame_subtype = (fc >> 4) & 0b1111   # bits 4-7

        # Source MAC address (bytes 10-15)
        mac_bytes = dot11_header[10:16]
        mac = ':'.join(f"{b:02x}" for b in mac_bytes)

        dst_mac_bytes = dot11_header[16:22]
        dst_mac = ':'.join(f"{b:02x}" for b in dst_mac_bytes)


        return frame_type, frame_subtype, mac, dst_mac

    @staticmethod
    def parse_tagged_parameters(packet, radiotap_len):
        ssid = None
        channel = None
        security = []
        vendor_specific_found = False

        security_map = {
            48: "WPA2/PSK",
            50: "WPA/PSK"
        }

        offset = radiotap_len + 24 + 12
        while offset + 2 <= len(packet):
            tag_number = packet[offset]
            tag_length = packet[offset + 1]
            tag_data = packet[offset + 2 : offset + 2 + tag_length]

            if tag_number == 0:
                try:
                    ssid = tag_data.decode(errors="ignore").strip()
                except:
                    ssid = None
            elif tag_number == 3: 
                if len(tag_data) >= 1:
                    channel = tag_data[0]
            elif tag_number in security_map: 
                sec_name = security_map[tag_number]
                if sec_name not in security:
                    security.append(sec_name)
            elif tag_number == 221:  # vendor specific
                vendor_specific_found = True

            offset += 2 + tag_length

        if vendor_specific_found and not security:
                security.append("Vendor Specific")

        return ssid, channel, security

