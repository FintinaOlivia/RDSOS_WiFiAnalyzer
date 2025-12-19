import threading
import csv
import os
import math
import time 

from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout,
    QGroupBox, QTableWidget, QTableWidgetItem,
    QSizePolicy
)
from PyQt6.QtCore import QObject, pyqtSignal, Qt
from PyQt6.QtGui import QColor, QIcon, QPixmap, QPainter

import pyqtgraph as pg

from wifi_scanner import WiFiScanner

import logging
logger = logging.getLogger(__name__)


STALE_TIMEOUT = 5 

class WiFiSignals(QObject):
    update_plot = pyqtSignal(dict)
    update_network = pyqtSignal(str, str, int, list, int, int)


def get_vendor_table(filename="vendors.csv"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)

    csv_path = os.path.join(parent_dir, "resources", filename)

    vendor_table = {}

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            prefix = row["Mac Prefix"].strip().upper()
            vendor = row["Vendor Name"].strip()

            vendor_table[prefix] = vendor

    return vendor_table


def _signal_icon(color, size=12):
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(color)
    p.setPen(Qt.PenStyle.NoPen)
    p.drawEllipse(0, 0, size, size)
    p.end()
    return QIcon(pix)


def _rssi_color(rssi):
    if rssi > -50:
        return QColor("green")
    elif rssi > -70:
        return QColor("orange")
    return QColor("red")


class WifiAnalyzerTab(QWidget):
    def __init__(self, interface="wlp3s0", vendor_table=None):
        super().__init__()

        self.vendor_table = vendor_table or get_vendor_table()
        self.curves = {}
        self.scanner = None

        main_layout = QHBoxLayout(self)

        plot_box = QGroupBox("WiFi Channel Analyzer")
        plot_layout = QVBoxLayout(plot_box)

        self.plot = pg.PlotWidget()
        self.plot.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding
        )
        self.plot.setLabel("left", "Signal Strength (dBm)")
        self.plot.setLabel("bottom", "Channel")
        self.plot.setXRange(1, 14)
        self.plot.setYRange(-100, -20)
        self.plot.showGrid(x=True, y=True)

        plot_layout.addWidget(self.plot)

        self.network_table = QTableWidget(0, 7)
        self.network_table.setHorizontalHeaderLabels([
            "Signal",
            "MAC",
            "Strength (dBm)",
            "Vendor",
            "Security",
            "Freq",
            "Channel"
        ])
        self.network_table.setColumnWidth(0, 50)
        
        self.network_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.network_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.network_table.horizontalHeader().setStretchLastSection(True)
        self.network_table.setAlternatingRowColors(True)

        main_layout.addWidget(plot_box, 3)
        main_layout.addWidget(self.network_table, 2)

        self.signals = WiFiSignals()
        self.signals.update_plot.connect(self.update_plot)
        self.signals.update_network.connect(self.update_network)

        self.color_map = pg.colormap.get("viridis")
        self.color_index = 0

        self.scanner = WiFiScanner(
            interface,
            ui_callback=self._emit_plot,
            list_callback=self._emit_network
        )

        threading.Thread(
            target=self.scanner.start,
            daemon=True
        ).start()

    def on_tab_activated(self):
        if not self.scanner.stop_flag:
            self.start_sniffing()

    def on_tab_deactivated(self):
        self.scanner.stop_sniffing()

    def _emit_plot(self, data):
        self.signals.update_plot.emit(data)

    def _emit_network(self, ssid, mac, rssi, security, freq, channel):
        self.signals.update_network.emit(
            ssid, mac, rssi, security, freq, channel
        )

    def update_plot(self, ssid_channels):
        attenuation = 40
        channels = range(1, 28)

        for ssid, channel_data in list(ssid_channels.items()):
            for center_ch, rssi in list(channel_data.items()):
                key = f"{ssid}_{center_ch}"

                if key not in self.curves:
                    color = self.color_map.map(
                        (self.color_index % 200) / 200,
                        mode="qcolor"
                    )
                    self.color_index += 10

                    curve = self.plot.plot(
                        pen=pg.mkPen(color=color, width=2)
                    )
                    label = pg.TextItem(
                        f"{ssid} (ch {center_ch})",
                        color=color
                    )
                    self.plot.addItem(label)

                    self.curves[key] = {
                        "curve": curve,
                        "label": label
                    }

                if center_ch <= 14:
                    a = -8.0   
                else:
                    a = -1.5  

                xs, ys = [], []
                for ch in channels:
                    y = a * (ch - center_ch) ** 2 + rssi
                    xs.append(ch)
                    ys.append(y)

                entry = self.curves[key]
                entry["curve"].setData(xs, ys)

                if not hasattr(entry["curve"], "_tooltip_set"):
                    entry["curve"].setToolTip(f"{ssid} (ch {center_ch})")
                    entry["curve"].setFillLevel(-120)
                    fill_color = pg.mkColor(entry["curve"].opts["pen"].color())
                    fill_color.setAlpha(60)
                    entry["curve"].setBrush(pg.mkBrush(fill_color))
                    entry["curve"]._tooltip_set = True 

                peak = max(ys)
                peak_ch = xs[ys.index(peak)]
                entry["label"].setPos(peak_ch + 0.2, peak)



    def update_network(self, ssid, mac, rssi, security, freq, channel):
        vendor = self.vendor_table.get(mac[:8].upper(), "Unknown")
        logging.debug(
        f"Debugging list_callback with SSID={ssid}, MAC={mac}, RSSI={rssi}, "
        f"Security={security}, Freq={freq}, Channel={channel}"
        )

        for row in range(self.network_table.rowCount()):
            if self.network_table.item(row, 1).text() == mac:
                self.network_table.item(row, 2).setText(str(rssi))
                self.network_table.item(row, 0).setIcon(
                    _signal_icon(_rssi_color(rssi))
                )
                return

        row = self.network_table.rowCount()
        self.network_table.insertRow(row)

        signal_item = QTableWidgetItem()
        signal_item.setIcon(
            _signal_icon(_rssi_color(rssi))
        )
        signal_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.network_table.setItem(row, 0, signal_item)

        values = [
            mac,
            str(rssi),
            vendor,
            ",".join(security) if security else "Open",
            str(freq),
            str(channel)
        ]

        for col, val in enumerate(values, start=1):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.network_table.setItem(row, col, item)
