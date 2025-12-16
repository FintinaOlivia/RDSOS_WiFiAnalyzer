import threading
import time
from scapy.all import *
from collections import defaultdict
import time
import matplotlib.pyplot as plt

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

    def set_channel(self, ch):
        import os
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
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            ssid = pkt[Dot11Elt].info.decode(errors="ignore").strip()
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

            current_timestamp = time.time()
            self.signal_counter[ssid][channel] = current_timestamp
            self.ssid_channels[ssid][channel] = rssi

            expire_time = current_timestamp - 30

            for s in list(self.signal_counter.keys()):
                for ch in list(self.signal_counter[s].keys()):
                    if self.signal_counter[s][ch] < expire_time:
                        del self.signal_counter[s][ch]
                        del self.ssid_channels[s][ch]

                if not self.signal_counter[s]:
                    del self.signal_counter[s]
                if not self.ssid_channels[s]:
                    del self.ssid_channels[s]


            if self.ui_callback:
                self.ui_callback(self.ssid_channels)
 
                self.list_callback(ssid, mac, rssi, security, freq, channel)


    def start(self):
        self.stop_flag = False

        threading.Thread(target=self.channel_hopper, daemon=True).start()

        sniff(iface=self.interface, prn=self.handle_packet, monitor=True)


    def stop(self):
        self.stop_flag = True

    def get_channels(self, ssid):
        return sorted(self.ssid_channels.get(ssid, []))
