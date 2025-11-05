import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget,
    QHBoxLayout, QPushButton, QLineEdit, QFileDialog, QMessageBox, QLabel, QProgressBar
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineProfile, QWebEngineDownloadRequest
from PyQt6.QtCore import Qt, QUrl, QPoint, QTimer

class Browser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setWindowTitle("Simple Qt Browser")
        self.setGeometry(100, 100, 1000, 700)
        
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        
        self.browser = QWebEngineView(self.central_widget)
        self.browser.setUrl(QUrl("https://www.google.com"))
        self.browser.urlChanged.connect(self.update_url_bar)
        self.browser.page().profile().downloadRequested.connect(self.handle_download)
        
        self.create_navigation_bar()
        self.create_download_status()
        
        self.layout.addWidget(self.browser)
        
        self.overlay = DragOverlay(self)
        self.overlay.setGeometry(0, 0, self.width(), 40)
        self.overlay.show()

    def create_navigation_bar(self):
        nav_bar = QWidget(self.central_widget)
        nav_bar.setFixedHeight(40)
        nav_layout = QHBoxLayout(nav_bar)
        nav_layout.setContentsMargins(5, 0, 5, 0)
        nav_layout.setSpacing(5)
        
        self.back_button = QPushButton("\u25C0", self)
        self.back_button.setFixedSize(30, 30)
        self.back_button.clicked.connect(self.browser.back)
        
        self.reload_button = QPushButton("\u27F3", self)
        self.reload_button.setFixedSize(30, 30)
        self.reload_button.clicked.connect(self.browser.reload)
        
        self.url_bar = QLineEdit(self)
        self.url_bar.returnPressed.connect(self.load_url)
        
        nav_layout.addWidget(self.back_button)
        nav_layout.addWidget(self.reload_button)
        nav_layout.addWidget(self.url_bar, 1)
        
        self.layout.insertWidget(0, nav_bar)
    
    def create_download_status(self):
        self.download_label = QLabel("", self)
        self.download_label.setVisible(False)
        
        self.download_progress = QProgressBar(self)
        self.download_progress.setVisible(False)
        
        self.layout.addWidget(self.download_label)
        self.layout.addWidget(self.download_progress)
    
    def load_url(self):
        url = self.url_bar.text()
        if not url.startswith("http"):
            if "." in url:
                url = "https://" + url
            else:
                url = f"https://www.google.com/search?q={url}"
        self.browser.setUrl(QUrl(url))
    
    def update_url_bar(self, qurl):
        self.url_bar.setText(qurl.toString())
    
    def handle_download(self, download: QWebEngineDownloadRequest):
        save_path, _ = QFileDialog.getSaveFileName(self, "Save File", download.suggestedFileName())
        if save_path:
            download.setDownloadDirectory(save_path.rsplit("/", 1)[0])
            download.setDownloadFileName(save_path.rsplit("/", 1)[-1])
            download.accept()
            
            self.download_label.setText(f"Downloading: {download.suggestedFileName()}")
            self.download_label.setVisible(True)
            self.download_progress.setVisible(True)
            self.download_progress.setValue(0)
            
            self.monitor_download(download)
    
    def monitor_download(self, download):
        self.download_timer = QTimer(self)
        self.download_timer.timeout.connect(lambda: self.update_download_progress(download))
        self.download_timer.start(500)
    
    def update_download_progress(self, download):
        if download.isFinished():
            self.download_timer.stop()
            self.download_label.setText("Download Complete")
            self.download_progress.setValue(100)
        elif download.totalBytes() > 0:
            progress = int((download.receivedBytes() / download.totalBytes()) * 100)
            self.download_progress.setValue(progress)
    
    def resizeEvent(self, event):
        self.overlay.setGeometry(0, 0, self.width(), 40)
        super().resizeEvent(event)

class DragOverlay(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self._dragging = False
        self._drag_position = QPoint()
        self.setFixedHeight(40)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and event.position().y() < 40:
            self._dragging = True
            self._drag_position = event.globalPosition().toPoint() - self.window().pos()
            event.accept()

    def mouseMoveEvent(self, event):
        if self._dragging and event.buttons() & Qt.MouseButton.LeftButton:
            self.window().move(event.globalPosition().toPoint() - self._drag_position)
            event.accept()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._dragging = False
            event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Browser()
    window.show()
    sys.exit(app.exec())
