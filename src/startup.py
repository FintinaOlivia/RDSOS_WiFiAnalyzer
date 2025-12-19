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
        self.resize(1800, 800)

        self.tabs = QTabWidget()
        self.tabs.addTab(WifiAnalyzerTab(), "WiFi Analyzer")
        self.tabs.addTab(PacketSnifferTab(), "Package Sniffer")

        self.setCentralWidget(self.tabs)
        self.tabs.currentChanged.connect(self.on_tab_changed)

        self.previous_tab_index = 0

    def on_tab_changed(self, index):
        previous_widget = self.tabs.widget(self.previous_tab_index)
        if hasattr(previous_widget, "on_tab_closed"):
            previous_widget.on_tab_closed()

        current_widget = self.tabs.widget(index)
        if hasattr(current_widget, "on_tab_activated"):
            current_widget.on_tab_activated()

        self.previous_tab_index = index

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
