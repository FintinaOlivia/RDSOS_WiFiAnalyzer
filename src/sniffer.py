from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QTabWidget,
    QListWidget, QLabel, QComboBox,
    QTableWidget, QTableWidgetItem,
    QGroupBox, QSizePolicy
)

class PacketSnifferTab(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)

        dropdown_layout = QHBoxLayout()

        self.layer_combo = QComboBox()
        self.layer_combo.addItems(["All Layers", "Ethernet", "IP", "TCP", "UDP"])

        self.interface_combo = QComboBox()
        self.interface_combo.addItems(["wlp3s0", "wlan0mon", "eth0"])

        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Managed", "Monitor"])

        dropdown_layout.addWidget(QLabel("Layer:"))
        dropdown_layout.addWidget(self.layer_combo)
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
