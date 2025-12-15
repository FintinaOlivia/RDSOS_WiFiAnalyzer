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

    def __init__(self, iface, channel, mode):
        super().__init__()
        self.iface = iface
        self.channel = channel
        self.mode = mode
        self._running = True

    def run(self):
        sniff(
            iface=self.iface,
            prn=self.process_packet,
            store=False,
            stop_filter=lambda _: not self._running,
        )

    def process_packet(self, pkt):
        if not self._running:
            return True

        layer = pkt.name
        src_mac = dst_mac = src_ip = dst_ip = ""
        ttl = src_port = dst_port = payload = ""

        if pkt.haslayer(TCP):
            layer = "TCP"
        elif pkt.haslayer(UDP):
            layer = "UDP"
        elif pkt.haslayer(IP):
            layer = "IP"
        elif pkt.haslayer(Dot11):
            layer = "802.11"

        if pkt.haslayer(Dot11):
            src_mac = pkt.addr2 or ""
            dst_mac = pkt.addr1 or ""
        elif pkt.haslayer(Ether):
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst

        if pkt.haslayer(IP):
            ip = pkt[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            ttl = ip.ttl

        if pkt.haslayer(TCP):
            l4 = pkt[TCP]
            src_port = l4.sport
            dst_port = l4.dport
            payload = bytes(l4.payload)[:100].decode(errors="ignore")
        elif pkt.haslayer(UDP):
            l4 = pkt[UDP]
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

        time.sleep(1)

    def stop(self):
        self._running = False

