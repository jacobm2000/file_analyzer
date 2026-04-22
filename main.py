import sys
import os
import funcs
from PyQt5 import QtCore
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout,
    QPushButton, QLabel, QFileDialog
)
from pathlib import Path



class SimpleScanner(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Simple File Scanner")
        self.setGeometry(300, 300, 400, 150)

        self.file_path = None

        layout = QVBoxLayout()

        # Label
        self.label = QLabel("No file selected")
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(self.label)

        # Load file button
        self.load_button = QPushButton("Load File")
        self.load_button.clicked.connect(self.load_file)
        layout.addWidget(self.load_button)

        # Scan button
        self.scan_button = QPushButton("Scan")
        self.scan_button.clicked.connect(self.scan_file)
        layout.addWidget(self.scan_button)
        
  
        self.setLayout(layout)

    def load_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path = file_path
            self.label.setText(f"Loaded: {os.path.basename(file_path)}")

    def scan_file(self):
        if not self.file_path:
            self.label.setText("No file selected!")
            return
        scan_output=""
        #files formats where entropy is a useful metric
        entropy_formats = [".exe", ".dll", ".ps1", ".bat", ".js", ".vbs", ".txt", ".json"]
 
        if (Path(self.file_path).suffix in entropy_formats):    
            entropy=funcs.file_entropy(self.file_path)
            scan_output+=f"Entropy:{entropy}\n\n"
        scan_output+=funcs.sig_check(self.file_path)
        
        file_size = os.path.getsize(self.file_path)
       
        self.label.setText(
            f"Scanned: {os.path.basename(self.file_path)} | Size: {file_size} bytes \n\n Results\n\n {scan_output}"
        )

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SimpleScanner()
    window.show()
    sys.exit(app.exec_())