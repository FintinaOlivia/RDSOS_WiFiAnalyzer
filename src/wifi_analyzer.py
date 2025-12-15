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
        self.setMinimumSize(300, 300)
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

        list_box = QGroupBox("Detected Networks")
        list_layout = QVBoxLayout()
        self.network_list = QListWidget()
        list_layout.addWidget(self.network_list)
        list_box.setLayout(list_layout)

        main_layout.addWidget(graphic_box, 2)
        main_layout.addWidget(list_box, 1)
