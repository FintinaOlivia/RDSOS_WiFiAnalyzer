from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QTabWidget,
    QListWidget, QLabel, QComboBox,
    QTableWidget, QTableWidgetItem,
    QGroupBox, QSizePolicy
)
from PyQt6.QtGui import QPainter, QColor

class SignalCanvas(QWidget):
    def __init__(self):
        super().__init__()
        self.setMinimumSize(250, 250)
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Expanding)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(30, 30, 30))
        painter.setPen(QColor(0, 200, 0))

        w, h = self.width(), self.height()
        for i in range(1, 6):
            painter.drawEllipse(
                w // 2 - i * 40,
                h // 2 - i * 40,
                i * 80,
                i * 80
            )

class WifiAnalyzerTab(QWidget):
    def __init__(self):
        super().__init__()

        main_layout = QHBoxLayout(self)

        graphic_box = QGroupBox("Signal Visualization")
        graphic_layout = QVBoxLayout()
        graphic_layout.addWidget(SignalCanvas())
        graphic_box.setLayout(graphic_layout)

        self.network_table = QTableWidget()
        self.network_table.setColumnCount(7)
        self.network_table.setHorizontalHeaderLabels([
            "Signal",
            "MAC",
            "Strength (dBm)",
            "Vendor",
            "Security",
            "Freq",
            "Channel"
        ])
        self.network_table.setColumnWidth(0, 35)
        self.network_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.network_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.network_table.horizontalHeader().setStretchLastSection(True)
        self.network_table.setAlternatingRowColors(True)

        main_layout.addWidget(graphic_box, 2)
        main_layout.addWidget(self.network_table, 1)

    def make_signal_icon(color: QColor, size=12):
        pix = QPixmap(size, size)
        pix.fill(Qt.GlobalColor.transparent)

        painter = QPainter(pix)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(color)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(0, 0, size, size)
        painter.end()

        return QIcon(pix)

    def rssi_color(rssi):
        if rssi is None:
            return QColor("gray")
        if rssi > -50:
            return QColor("green")
        elif rssi > -70:
            return QColor("orange")
        else:
            return QColor("red")

    def update_network(self, mac, rssi, vendor, security, freq, channel):
        for row in range(self.network_table.rowCount()):
            if self.network_table.item(row, 1).text() == mac:
                self.network_table.item(row, 2).setText(str(rssi))
                self.network_table.item(row, 0).setIcon(
                    make_signal_icon(rssi_color(rssi))
                )
                return

        row = self.network_table.rowCount()
        self.network_table.insertRow(row)

        signal_item = QTableWidgetItem()
        signal_item.setToolTip(f"RSSI: {rssi} dBm")
        signal_item.setIcon(make_signal_icon(rssi_color(rssi)))
        signal_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.network_table.setItem(row, 0, signal_item)

        values = [
            mac,
            str(rssi),
            vendor or "Unknown",
            security or "Unknown",
            freq or "Unknown",
            channel or "Unknown"
        ]

        for col, val in enumerate(values, start=1):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.network_table.setItem(row, col, item)

