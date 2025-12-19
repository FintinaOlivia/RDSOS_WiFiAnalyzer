import sys
import subprocess
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QTabWidget,
    QListWidget, QLabel, QComboBox,
    QTableWidget, QTableWidgetItem,
    QGroupBox, QSizePolicy
)
from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import *
import logging

from scapy.layers.dot11 import Dot11
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.l2 import Ether

from wifi_packet_parser import WiFiPacketParser
from header_parser import HeaderParser

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO,  
    format="%(asctime)s [%(levelname)s] %(message)s"
)

class PacketSnifferTab(QWidget):
    def __init__(self):
        super().__init__()
        self.sniffing = False
        self.sniffer_thread = None

        layout = QVBoxLayout(self)

        dropdown_layout = QHBoxLayout()

        self.channel_combo = QComboBox()
        self.channel_combo.addItems([str(i) for i in range(1, 14)])

        self.interface_combo = QComboBox()
        # self.interface_combo.addItems(get_if_list())
        self.interface_combo.addItems(["wlp3s0"])

        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Monitor", "Managed"])

        dropdown_layout.addWidget(QLabel("Channels:"))
        dropdown_layout.addWidget(self.channel_combo)
        dropdown_layout.addWidget(QLabel("Interface:"))
        dropdown_layout.addWidget(self.interface_combo)
        dropdown_layout.addWidget(QLabel("Mode:"))
        dropdown_layout.addWidget(self.mode_combo)

        layout.addLayout(dropdown_layout)

        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels(
            ["Layer", "Source MAC", "Destination MAC", "Source IP", "Destination IP",
             "TTL", "Source Port", "Destination Port", "Payload"]
        )

        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)

        layout.addWidget(self.table)

        self.channel_combo.currentIndexChanged.connect(self.on_settings_changed)
        self.interface_combo.currentIndexChanged.connect(self.on_settings_changed)
        self.mode_combo.currentIndexChanged.connect(self.on_settings_changed)

    def on_tab_activated(self):
        if not self.sniffing:
            self.start_sniffing()

    def on_tab_deactivated(self):
        self.stop_sniffing()

    def on_settings_changed(self):
        if self.sniffing:
            self.restart_sniffing()

    def start_sniffing(self):
        interface = self.interface_combo.currentText()
        channel = self.channel_combo.currentText()
        mode = self.mode_combo.currentText()

        if mode == "Monitor":
            subprocess.run(["./scripts/monitor_mode.sh"], check=True)
        else:
            subprocess.run(["./scripts/managed_mode.sh"], check=True)

        self.sniffer_thread = SnifferThread(interface, channel, mode)
        self.sniffer_thread.packet_received.connect(self.handle_packet)
        self.sniffer_thread.start()

        self.sniffing = True
    
    def stop_sniffing(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()
            self.sniffer_thread = None

        self.sniffing = False

    def restart_sniffing(self):
        self.stop_sniffing()
        self.start_sniffing()

    def handle_packet(self, packet_info):
        row = self.table.rowCount()
        self.table.insertRow(row)

        values = [
            packet_info["layer"],
            packet_info["src_mac"],
            packet_info["dst_mac"],
            packet_info["src_ip"],
            packet_info["dst_ip"],
            packet_info["ttl"],
            packet_info["src_port"],
            packet_info["dst_port"],
            packet_info["payload"],
        ]

        for col, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            self.table.setItem(row, col, item)

        if self.table.rowCount() > 200:
            self.table.removeRow(0)



class SnifferThread(QThread):
    packet_received = pyqtSignal(dict)

    def __init__(self, interface, channel, mode):
        super().__init__()
        self.interface = interface
        self.channel = channel
        self.mode = mode
        self.stop_flag = False

    def run(self):
        # sniff(iface=self.interface, prn=self.process_packet, store=False, stop_filter=lambda _: self.stop_flag)
        if self.mode == "Monitor":
            self.sniff_manual(self.interface, self.process_packet_monitor)
        else:
            self.sniff_manual(self.interface, self.process_packet_managed)
        
    def sniff_manual(self, interface, callback):
        logger.info("Sniffing in mode %s", self.mode)
        self.stop_flag = False

        while not self.stop_flag:
            try:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                sock.bind((interface, 0))
                sock.setblocking(False)
                logger.debug("Socket bound to interface %s", interface)
                break 
            except OSError as e:
                logger.error("Socket: Failed to bind socket on interface %s: %s", interface, e)
                logger.debug("Socket: Retrying in 1 second...")
                time.sleep(1)
            except Exception as e:
                logger.error("Socket: Unexpected socket error: %s", e)
                return

        while not self.stop_flag:
            try:
                try:
                    ready, _, _ = select.select([sock], [], [], 0.5)
                    if ready:
                        packet, _ = sock.recvfrom(65535)
                        callback(packet)
                except Exception as e:
                    logger.error("Socket error: %s", e)
            except socket.timeout:
                continue
            except Exception as e:
                logger.error("Socket: error while receiving: %s", e)

        sock.close()
        logger.info("Socket: socket closed")

    def process_packet_monitor(self, packet):
        src_ip = dst_ip = ""
        ttl = ""
        src_port = dst_port =  ""
        payload = ""

        has_dot11 = False
        has_ip = False
        has_tcp = False
        has_udp = False

        rssi, rt_len = WiFiPacketParser.parse_radiotap(packet)
        frame_type, frame_subtype, src_mac, dst_mac = WiFiPacketParser.parse_80211_header(packet, rt_len)

        if frame_type is not None:
            has_dot11 = True

        offset = rt_len + 24

        if len(packet) >= offset + 8 and packet[offset+6:offset+8] == b"\x08\x00":
            ip = HeaderParser.parse_ip(packet, offset + 8)
            if ip:
                logger.debug("Protocols: IP identified")
                has_ip = True

        if has_ip:
            if ip["protocol"] == 6:
                tcp = HeaderParser.parse_tcp(packet, ip["offset"])
                if tcp:
                    logger.debug("Protocols: TCP identified")
                    has_tcp = True
            elif ip["protocol"] == 17:
                udp = HeaderParser.parse_udp(packet, ip["offset"])
                if udp:
                    logger.debug("Protocols: UDP identified")
                    has_udp = True

        if has_tcp:
            layer = "TCP"
            src_port = tcp["src_port"]
            dst_port = tcp["dst_port"]
            payload = tcp["payload"]
        elif has_udp:
            layer = "UDP"
            src_port = udp["src_port"]
            dst_port = udp["dst_port"]
        elif has_ip:
            layer = "IP"
            src_ip = ip["src_ip"]
            dst_ip = ip["dst_ip"]
            ttl = ip["ttl"]
        elif has_dot11:
            layer = "802.11"
        else:
            layer = "RadioTap/Raw/Unverified"

        self.packet_received.emit({
            "layer": layer,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ttl": ttl,
            "src_port": src_port,
            "dst_port": dst_port,
            "payload": payload
        })
        time.sleep(1)

    def process_packet_managed(self, packet):
        eth_len = 14
        if len(packet) < eth_len:
            return

        eth = HeaderParser.parse_ethernet(packet)
        if not eth:
            return

        protocol = eth["protocol"]
        offset = eth["offset"]
        dst_mac = eth["dst_mac"]
        src_mac = eth["src_mac"]

        payload = packet[eth_len:]
        layer = "Ethernet"
        src_ip = dst_ip = ttl = ""
        src_port = dst_port = ""

        if protocol == 0x0800:
            ip = HeaderParser.parse_ip(packet, offset)
            if not ip:
                return

            layer = "IP"
            src_ip = ip["src_ip"]
            dst_ip = ip["dst_ip"]
            ttl = ip["ttl"]
            protocol = ip["protocol"]

            offset = ip["offset"]
            if protocol == 6:
                tcp = HeaderParser.parse_tcp(packet, offset)
                if not tcp:
                    return

                layer = "TCP"
                src_port = tcp["src_port"]
                dst_port = tcp["dst_port"]
                payload_data = tcp["payload"]

            elif protocol == 17:
                udp = HeaderParser.parse_udp(packet, offset)
                if not udp:
                    return

                layer = "UDP"
                src_port = udp["src_port"]
                dst_port = udp["dst_port"]
                payload_data = b""

            else:
                payload_data = b""

            payload = payload_data.decode(errors="ignore") if payload_data else ""

        self.packet_received.emit({
            "layer": layer,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ttl": ttl,
            "src_port": src_port,
            "dst_port": dst_port,
            "payload": payload
        })
        time.sleep(0.5)

    def process_packet(self, packet):
        if self.stop_flag:
            return True

        layer = packet.name
        src_mac = dst_mac = src_ip = dst_ip = ""
        ttl = src_port = dst_port = payload = ""

        if packet.haslayer(TCP):
            layer = "TCP"
        elif packet.haslayer(UDP):
            layer = "UDP"
        elif packet.haslayer(IP):
            layer = "IP"
        elif packet.haslayer(Dot11):
            layer = "802.11"

        if packet.haslayer(Dot11):
            src_mac = packet.addr2 or ""
            dst_mac = packet.addr1 or ""
        elif packet.haslayer(Ether):
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

        if packet.haslayer(IP):
            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            ttl = ip.ttl

        if packet.haslayer(TCP):
            l4 = packet[TCP]
            src_port = l4.sport
            dst_port = l4.dport
            payload = bytes(l4.payload)[:100].decode(errors="ignore")
        elif packet.haslayer(UDP):
            l4 = packet[UDP]
            src_port = l4.sport
            dst_port = l4.dport

        self.packet_received.emit({
            "layer": layer,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ttl": ttl,
            "src_port": src_port,
            "dst_port": dst_port,
            "payload": payload
        })

        time.sleep(0.5)

    def stop(self):
        self.stop_flag = True

