import sys
import os
import funcs
from PyQt5 import QtCore
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout,
    QPushButton, QLabel, QFileDialog,QTextEdit
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
        self.results_box.clear()
        #files formats where entropy is a useful metric
        entropy_formats = [".exe", ".dll", ".ps1", ".bat", ".js", ".vbs", ".txt", ".json"]
        file_ext=Path(self.file_path).suffix
      
        file_info=f"file type: {str(file_ext)}<br>"
        file_size = os.path.getsize(self.file_path)
        file_info+=f"file size: {str(file_size)} Bytes<br>"
        if (file_ext in entropy_formats):    
            entropy=funcs.file_entropy(self.file_path)
            entropy_level=funcs.entropy_level(entropy)
            file_info+=f"Entropy:{str(entropy)} | {entropy_level}\n\n"
        
       
       
 
        scan_output=funcs.sig_check(self.file_path)
        
        
        
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