import threading
import time
import os
from typing import Any

from scapy.all import *
from collections import defaultdict
import time
import matplotlib.pyplot as plt
import logging
import socket

from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt

from wifi_packet_parser import WiFiPacketParser

# logging.basicConfig(
#     level=logging.info,  
#     format="%(asctime)s [%(levelname)s] %(message)s"
# )
logger = logging.getLogger(__name__)

CHANNELS = list(range(1, 14))  
CHANNELS_5G = [
     36, 40, 44, 48,           
     149, 153, 157, 161
    ]  
SCAN_CHANNELS = CHANNELS


class WiFiScanner:
    def __init__(self, interface, ui_callback=None, list_callback=None):
        self.interface = interface
        self.ui_callback = ui_callback
        self.list_callback = list_callback
        self.stop_flag = False
        self.plot_timer = None
        self.refresh_signals = time.time()
        self.ssid_channels = defaultdict(dict)
        self.signal_counter = defaultdict(dict)
        self.lock = threading.Lock()

    def set_channel(self, ch):
        os.system(f"sudo iw dev {self.interface} set channel {ch}")

    def channel_hopper(self):
        idx = 0
        while not self.stop_flag:
            ch = SCAN_CHANNELS[idx]

            try:
                self.set_channel(ch)
            except:
                pass

            idx = (idx + 1) % len(SCAN_CHANNELS)
            time.sleep(0.20)

    def handle_packet(self, pkt):
        logger.debug("Received packet, length=%d", len(pkt))

        rssi, radiotap_len = WiFiPacketParser.parse_radiotap(pkt)
        if radiotap_len is None:
            logger.debug("Packet too short for Radiotap header, skipping")
            return

        frame_type, frame_subtype, mac, _ = WiFiPacketParser.parse_80211_header(pkt, radiotap_len)
        # Only process Beacon (8) or Probe Response (5)
        if frame_type != 0 or frame_subtype not in (5, 8):
            return

        ssid, channel, security = WiFiPacketParser.parse_tagged_parameters(pkt, radiotap_len)

        logging.debug(f"Parsed parameters: SSID={ssid}, Channel={channel}, Security={security}")

        if not ssid or not channel:
            return

        freq = 2412 + (channel - 1) * 5
        timestamp = time.time()
        logging.debug(f"Calculated frequency: {freq} MHz, Timestamp: {timestamp}")


        self.signal_counter.setdefault(ssid, {})[channel] = timestamp
        self.ssid_channels.setdefault(ssid, {})[channel] = rssi
        self.updateUI(channel, freq, mac, rssi, security, ssid, timestamp)

    def updateUI(self, channel: Any | None, freq: int | Any, mac, rssi, security: list[Any], ssid: Any | None,
                 timestamp: float):
        expire = timestamp - 30

        for s in list(self.signal_counter.keys()):
            for ch in list(self.signal_counter[s].keys()):
                if self.signal_counter[s][ch] < expire:
                    del self.signal_counter[s][ch]
                    del self.ssid_channels[s][ch]

            if not self.signal_counter[s]:
                del self.signal_counter[s]
            if not self.ssid_channels[s]:
                del self.ssid_channels[s]

        if self.ui_callback:
            self.ui_callback(self.ssid_channels)
            self.list_callback(ssid, mac, rssi, security, freq, channel)

    def handle_packet_scapy(self, pkt):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            ssid = pkt[Dot11Elt].debug.decode(errors="ignore").strip()
            if not ssid:
                return

            mac = pkt.addr2

            stats = (pkt[Dot11Beacon].network_stats()
                    if pkt.haslayer(Dot11Beacon)
                    else pkt[Dot11ProbeResp].network_stats())

            channel = stats.get("channel")
            security = stats.get("crypto", [])
            freq = 2412 + (channel - 1) * 5

            if hasattr(pkt, "dBm_AntSignal"):
                rssi = pkt.dBm_AntSignal

            timestamp = time.time()
            self.signal_counter[ssid][channel] = timestamp
            self.ssid_channels[ssid][channel] = rssi
            self.updateUI(channel, freq, mac, rssi, security, ssid, timestamp)


    def start(self):
        self.stop_flag = False

        threading.Thread(target=self.channel_hopper, daemon=True).start()

        # sniff(iface=self.interface, prn=self.handle_packet, monitor=True)

        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.bind((self.interface, 0))
        logger.debug("Bound socket")

        while not self.stop_flag:
            try:
                pkt = s.recv(4096)
                self.handle_packet(pkt)
            except socket.timeout:
                continue 
            except Exception:
                continue 

        s.close()

    def stop(self):
        self.stop_flag = True

    def get_channels(self, ssid):
        return sorted(self.ssid_channels.get(ssid, []))
