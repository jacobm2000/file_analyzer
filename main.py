import sys
import os
import funcs
import hashlib
import time
from PyQt5 import QtCore
from PyQt5.QtGui import QFont 
from PyQt5.QtWidgets import (
    QApplication,QWidget, QVBoxLayout,
    QPushButton, QLabel, QFileDialog,QTextEdit,QHBoxLayout
)
from pathlib import Path




class SimpleScanner(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Simple File Scanner")
        self.setGeometry(500, 600, 600, 400)
        self.file_path = None
        self.setAcceptDrops(True)
        layout = QVBoxLayout()

        self.label = QLabel("No file selected")
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        file_font = QFont("Arial", 14, QFont.Weight.Bold)
        self.label.setFont(file_font)
        layout.addWidget(self.label)
        # Scrollable Results Box
        self.results_box = QTextEdit()
        self.results_box.setReadOnly(True)
       
        layout.addWidget(self.results_box)

        self.status_label = QLabel("")
        self.status_label.setAlignment(QtCore.Qt.AlignCenter)
        status_font = QFont("Arial", 10, QFont.Weight.Bold)
        self.status_label.setFont(status_font)
        layout.addWidget(self.status_label)

        button_layout = QHBoxLayout()
        #  Load file button
        self.load_button = QPushButton("Load File")
        self.load_button.clicked.connect(self.load_file)
        self.load_button.setIcon(self.style().standardIcon(QApplication.style().SP_DialogOpenButton))
        button_layout.addWidget(self.load_button)
        
        # Scan button
        self.scan_button = QPushButton("Scan")
        self.scan_button.clicked.connect(self.scan_file)
        self.scan_button.setEnabled(False)
        self.scan_button.setIcon(self.style().standardIcon(QApplication.style().SP_MediaPlay))
        button_layout.addWidget(self.scan_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
  
        
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()
            
    def dropEvent(self, event):
        file_path = event.mimeData().urls()[0].toLocalFile()
        self.file_path = file_path
        self.label.setText(f"Loaded: {os.path.basename(file_path)}")
        self.label.setToolTip(file_path)
        self.scan_button.setEnabled(True)
        
    def get_sha256(self,file_path):
        sha256 = hashlib.sha256()
    
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
    
        return sha256.hexdigest()
    def color_severity(self,text):
            text = text.replace("HIGH", "<span style='color:red; font-weight:bold;'>High</span>")
            text = text.replace("MEDIUM", "<span style='color:orange; font-weight:bold;'>Moderate</span>")
            text = text.replace("LOW", "<span style='color:green; font-weight:bold;'>Low</span>")
            return text
    def load_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path = file_path
            self.label.setText(f"Loaded: {os.path.basename(file_path)}")
            self.label.setToolTip(self.file_path)
            self.scan_button.setEnabled(True)
    def scan_file(self):
        if not self.file_path:
            self.label.setText("No file selected!")
            return
        self.results_box.clear()
        self.status_label.setText("Scanning...")
        QApplication.processEvents()
        #files formats where entropy is a useful metric
        entropy_formats = [".exe", ".dll", ".ps1", ".bat", ".js", ".vbs", ".txt", ".json"]
        file_hash=self.get_sha256(self.file_path)
        file_info=f"SHA256: {file_hash}<br>"
        created = time.ctime(os.path.getctime(self.file_path))
        modified = time.ctime(os.path.getmtime(self.file_path))
        file_info+=f"""Date created: {created}<br>
        Last Modified: {modified}<br>
        """
        file_ext=Path(self.file_path).suffix
        file_info+=f"file type: {str(file_ext)}<br>"
        file_size = round(os.path.getsize(self.file_path)/1000,2)
        file_info+=f"file size: {str(file_size)} kB<br>"
        if (file_ext in entropy_formats):    
            entropy=funcs.file_entropy(self.file_path)
            entropy_level=funcs.entropy_level(entropy)
            file_info+=f"Entropy: {str(entropy)} ({entropy_level})<br><br>"
            # color codes entropy severity
            file_info = self.color_severity(file_info)
        
        scan=funcs.yara_check(self.file_path)
        scan_output=f"<h3>{len(scan)} detections</h3><br>"
        scan_output+=funcs.yara_to_string(scan)
        
        # color codes severity
        scan_output = self.color_severity(scan_output)
    
        
        self.results_box.setHtml(f"""
        <p style="font-size:16px; font-weight:bold; text-decoration: underline; text-align:center;">
        File Info
        </p>
        
        <p style="font-size:12px; text-align:center;">
        {file_info}
        </p>
        
         <p style="font-size:16px; font-weight:bold; text-decoration: underline; text-align:center;">
        File Analysis
        </p>
        
        <p style="font-size:12px; text-align:center;">
        {scan_output}
        </p>
        """
        )
        self.status_label.setText("Scan complete")
       
        
   
      

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SimpleScanner()
    window.show()
    sys.exit(app.exec_())