import sys
import os
import funcs
import hashlib
from PyQt5 import QtCore
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout,
    QPushButton, QLabel, QFileDialog,QTextEdit,QHBoxLayout
)
from pathlib import Path



class SimpleScanner(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Simple File Scanner")
        self.setGeometry(500, 600, 600, 400)

        self.file_path = None

        layout = QVBoxLayout()

        self.label = QLabel("No file selected")
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(self.label)
        # Scrollable Results Box
        self.results_box = QTextEdit()
        self.results_box.setReadOnly(True)
       
        layout.addWidget(self.results_box)


        button_layout = QHBoxLayout()
        #  Load file button
        self.load_button = QPushButton("Load File")
        self.load_button.clicked.connect(self.load_file)
        button_layout.addWidget(self.load_button)

        # Scan button
        self.scan_button = QPushButton("Scan")
        self.scan_button.clicked.connect(self.scan_file)
        button_layout.addWidget(self.scan_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
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

    def scan_file(self):
        if not self.file_path:
            self.label.setText("No file selected!")
            return
        self.results_box.clear()
        #files formats where entropy is a useful metric
        entropy_formats = [".exe", ".dll", ".ps1", ".bat", ".js", ".vbs", ".txt", ".json"]
        file_hash=self.get_sha256(self.file_path)
        file_info=f"SHA256: {file_hash}<br>"
        file_ext=Path(self.file_path).suffix
        file_info+=f"file type: {str(file_ext)}<br>"
        file_size = round(os.path.getsize(self.file_path)/1000,2)
        file_info+=f"file size: {str(file_size)} kB<br>"
        if (file_ext in entropy_formats):    
            entropy=funcs.file_entropy(self.file_path)
            entropy_level=funcs.entropy_level(entropy)
            file_info+=f"Entropy: {str(entropy)} ({entropy_level})\n\n"
            # color codes entropy severity
            file_info = self.color_severity(file_info)
 
        scan_output=funcs.sig_check(self.file_path)
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
    
       
        
   
      

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SimpleScanner()
    window.show()
    sys.exit(app.exec_())