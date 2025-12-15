import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QTabWidget,
    QListWidget, QLabel, QComboBox,
    QTableWidget, QTableWidgetItem,
    QGroupBox, QSizePolicy
)
from PyQt6.QtGui import QPainter, QColor
from PyQt6.QtCore import Qt

from sniffer import PacketSnifferTab
from wifi_analyzer import WifiAnalyzerTab


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("WiFi Analyzer & Packet Sniffer")
        self.resize(1500, 800)

        tabs = QTabWidget()
        tabs.addTab(WifiAnalyzerTab(), "WiFi Analyzer")
        tabs.addTab(PacketSnifferTab(), "Package Sniffer")

        self.setCentralWidget(tabs)


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
