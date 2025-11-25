# Gorstak's Browser - PyQt6 with tabs, video support, and fixed bookmarks

import sys
import ctypes
from ctypes import wintypes
import os
import re
import json
import traceback
import threading
import time
from urllib.parse import urlparse
import shutil

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".gorstak_browser")
CONFIG_FILE = os.path.join(CONFIG_DIR, "CONFIG_FILE")
CREDENTIALS_FILE = os.path.join(CONFIG_DIR, "credentials.json")


def _clear_stale_locks():
    """Clear stale lock files and cache that might be left from crashed sessions."""
    
    lock_files = [
        os.path.join(CONFIG_DIR, "storage", "lockfile"),
        os.path.join(CONFIG_DIR, "cache", "lockfile"),
        os.path.join(CONFIG_DIR, "storage", "GPUCache", "lockfile"),
        os.path.join(CONFIG_DIR, "cache", "GPUCache", "lockfile"),
    ]
    
    for lock_file in lock_files:
        try:
            if os.path.exists(lock_file):
                os.remove(lock_file)
        except:
            pass
    
    cache_dirs = [
        os.path.join(CONFIG_DIR, "storage", "GPUCache"),
        os.path.join(CONFIG_DIR, "cache", "GPUCache"),
        os.path.join(CONFIG_DIR, "storage", "Service Worker"),
        os.path.join(CONFIG_DIR, "storage", "QuotaManager"),
        os.path.join(CONFIG_DIR, "storage", "IndexedDB"),
        os.path.join(CONFIG_DIR, "storage", "Cache"),
        os.path.join(CONFIG_DIR, "storage", "blob_storage"),
    ]
    
    for cache_dir in cache_dirs:
        try:
            if os.path.exists(cache_dir):
                shutil.rmtree(cache_dir, ignore_errors=True)
        except:
            pass
    
# Run cleanup before anything else
_clear_stale_locks()

os.makedirs(os.path.join(CONFIG_DIR, "storage"), exist_ok=True)
os.makedirs(os.path.join(CONFIG_DIR, "cache"), exist_ok=True)

# Now do the rest of the imports
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QToolButton, QMenu, QFileDialog,
    QMessageBox, QSizePolicy, QTabWidget, QTabBar
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import (
    QWebEnginePage, QWebEngineProfile, QWebEngineScript, QWebEngineSettings,
    QWebEngineUrlRequestInterceptor  # Added for ad blocking
)
from PyQt6.QtCore import Qt, QUrl, QSize, QTimer, QByteArray
from PyQt6.QtGui import QFont, QPixmap, QPainter, QIcon, QAction
from PyQt6.QtSvg import QSvgRenderer
from bs4 import BeautifulSoup


AD_DOMAINS = {
    # Major ad networks
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "google-analytics.com", "googletagmanager.com", "googletagservices.com",
    "adservice.google.com", "pagead2.googlesyndication.com",
    # Facebook tracking
    "facebook.net", "fbcdn.net", "connect.facebook.net",
    "pixel.facebook.com", "an.facebook.com",
    # Other ad networks
    "adsrvr.org", "adnxs.com", "rubiconproject.com", "pubmatic.com",
    "openx.net", "casalemedia.com", "criteo.com", "criteo.net",
    "outbrain.com", "taboola.com", "mgid.com", "revcontent.com",
    "amazon-adsystem.com", "media.net", "contextweb.com",
    "advertising.com", "adcolony.com", "unity3d.com", "applovin.com",
    "mopub.com", "inmobi.com", "chartboost.com",
    # Tracking/Analytics
    "scorecardresearch.com", "quantserve.com", "hotjar.com",
    "fullstory.com", "mouseflow.com", "crazyegg.com", "luckyorange.com",
    "mixpanel.com", "amplitude.com", "segment.io", "segment.com",
    "branch.io", "adjust.com", "appsflyer.com", "kochava.com",
    "newrelic.com", "nr-data.net", "bugsnag.com", "sentry.io",
    "rollbar.com", "raygun.com",
    # Social tracking
    "addthis.com", "sharethis.com", "addtoany.com",
    "twitter.com/i/adsct", "analytics.twitter.com",
    "linkedin.com/px", "snap.licdn.com",
    "tiktok.com/i18n/pixel", "analytics.tiktok.com",
    # Misc trackers
    "omtrdc.net", "demdex.net", "everesttech.net",  # Adobe
    "bing.com/bat.js", "bat.bing.com",  # Microsoft
    "yandex.ru/metrika", "mc.yandex.ru",  # Yandex
    "gemius.pl", "hit.gemius.pl",
    "2mdn.net", "serving-sys.com", "eyeota.net", "bluekai.com",
    "exelator.com", "crwdcntrl.net", "rlcdn.com", "pippio.com",
    "tapad.com", "adform.net", "adsymptotic.com", "adgrx.com",
    # Popup/overlay annoyances
    "pushwoosh.com", "onesignal.com", "pusher.com", "subscribers.com",
    "popads.net", "popcash.net", "propellerads.com",
}

AD_URL_PATTERNS = [
    r"/ads/", r"/ad/", r"/adserver", r"/advert", r"/banner",
    r"doubleclick", r"googlesyndication", r"googleads",
    r"/pagead/", r"/pixel", r"/tracking", r"/tracker",
    r"amazon-adsystem", r"/sponsored", r"smartadserver",
]


class AdBlocker(QWebEngineUrlRequestInterceptor):
    """Request interceptor to block ads and trackers"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.blocked_count = 0
        self.enabled = True
    
    def interceptRequest(self, info):
        if not self.enabled:
            return
            
        url = info.requestUrl().toString().lower()
        host = info.requestUrl().host().lower()
        
        # Check if host matches any ad domain
        for ad_domain in AD_DOMAINS:
            if host == ad_domain or host.endswith("." + ad_domain):
                info.block(True)
                self.blocked_count += 1
                return
        
        # Check URL patterns
        for pattern in AD_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                info.block(True)
                self.blocked_count += 1
                return


# Small SVG helpers
OVERFLOW_SVG = '<svg width="20" height="20"><path d="M6 10c0-1.1.9-2 2-2s2 .9 2 2-.9 2-2 2-2-.9-2-2z" fill="#ccc"/></svg>'
NEW_TAB_SVG = '<svg width="20" height="20"><path d="M11 3H9v6H3v2h6v6h2v-6h6V9h-6V3z" fill="#ccc"/></svg>'
CLOSE_SVG = '<svg width="12" height="12"><path d="M2 2l8 8M10 2l-8 8" stroke="#ccc" stroke-width="2"/></svg>'

def svg_icon(svg, size=20):
    r = QSvgRenderer(QByteArray(svg.encode()))
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    r.render(p)
    p.end()
    return QIcon(pix)


class CustomWebPage(QWebEnginePage):
    def __init__(self, profile, parent=None, browser=None):
        super().__init__(profile, parent)
        self._browser = browser
        
        settings = self.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.WebGLEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.Accelerated2dCanvasEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.FullScreenSupportEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.PlaybackRequiresUserGesture, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanOpenWindows, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.AllowRunningInsecureContent, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.AllowGeolocationOnInsecureOrigins, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.ScrollAnimatorEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.AllowWindowActivationFromJavaScript, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.ErrorPageEnabled, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.FocusOnNavigationEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.HyperlinkAuditingEnabled, False)
        
        self.featurePermissionRequested.connect(self._handle_permission_request)
    
    def _handle_permission_request(self, url, feature):
        self.setFeaturePermission(url, feature, QWebEnginePage.PermissionPolicy.PermissionGrantedByUser)
    
    def acceptNavigationRequest(self, url, nav_type, is_main_frame):
        return True
    
    def createWindow(self, window_type):
        if self._browser:
            return self._browser.create_new_tab()
        return None


class BrowserTab(QWebEngineView):
    def __init__(self, profile, browser, url=None):
        super().__init__()
        self._browser = browser
        page = CustomWebPage(profile, self, browser)
        self.setPage(page)
        
        self.loadFinished.connect(self._on_load_finished)
        self._cred_check_timer = None
        
        if url:
            self.setUrl(QUrl(url))
    
    def _on_load_finished(self, ok):
        if not ok or not self._browser:
            return
        
        url = self.url().toString().lower()
        domain = self._browser.credentials_manager.get_domain_from_url(url)
        creds = self._browser.credentials_manager.get_credentials(domain)
        
        if 'discord.com/login' in url or 'discord.com/register' in url:
            self._inject_discord_credentials(creds)
            return
        
        # Only skip if NOT on a login-related URL
        is_login_page = any(x in url for x in ['/login', '/signin', '/sign-in', '/auth', '/account/login', '/session', '/sso'])
        
        skip_app_domains = ['discord.com', 'discord.gg', 'discordapp.com']
        for skip in skip_app_domains:
            if skip in url and not is_login_page:
                return
        
        # Standard credential handling for all other sites including login pages
        self._inject_standard_credentials(creds)
    
    def _inject_discord_credentials(self, creds):
        """Special credential injection for Discord's React-based login."""
        # Capture script for Discord - waits for React to render
        capture_script = """
        (function() {
            if (window._gbrowserDiscordCapture) return;
            window._gbrowserDiscordCapture = true;
            
            function captureOnSubmit() {
                var form = document.querySelector('form');
                if (!form) return setTimeout(captureOnSubmit, 500);
                
                form.addEventListener('submit', function() {
                    try {
                        var inputs = document.querySelectorAll('input');
                        var email = '', pass = '';
                        inputs.forEach(function(inp) {
                            if (inp.type === 'email' || inp.name === 'email' || inp.autocomplete === 'email') email = inp.value;
                            if (inp.type === 'password') pass = inp.value;
                        });
                        if (email && pass) window._gbrowserCreds = {username: email, password: pass};
                    } catch(e) {}
                }, true);
            }
            captureOnSubmit();
        })();
        """
        self.page().runJavaScript(capture_script)
        
        # Schedule credential check
        if self._cred_check_timer:
            self._cred_check_timer.stop()
        self._cred_check_timer = QTimer()
        self._cred_check_timer.setSingleShot(True)
        self._cred_check_timer.timeout.connect(lambda: self._check_and_save_credentials())
        self._cred_check_timer.start(3000)
        
        # Auto-fill for Discord - wait for React to render inputs
        if creds:
            username = creds["username"].replace("\\", "\\\\").replace("'", "\\'").replace("\n", "")
            password = creds["password"].replace("\\", "\\\\").replace("'", "\\'").replace("\n", "")
            
            fill_script = f"""
            (function() {{
                function fillDiscord() {{
                    var inputs = document.querySelectorAll('input');
                    var emailInput = null, passInput = null;
                    
                    inputs.forEach(function(inp) {{
                        if (inp.type === 'email' || inp.name === 'email' || inp.autocomplete === 'email') emailInput = inp;
                        if (inp.type === 'password') passInput = inp;
                    }});
                    
                    if (!emailInput || !passInput) {{
                        setTimeout(fillDiscord, 500);
                        return;
                    }}
                    
                    // Simulate real user input for React
                    function setNativeValue(el, val) {{
                        var setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
                        setter.call(el, val);
                        el.dispatchEvent(new Event('input', {{bubbles: true}}));
                        el.dispatchEvent(new Event('change', {{bubbles: true}}));
                    }}
                    
                    setNativeValue(emailInput, '{username}');
                    setNativeValue(passInput, '{password}');
                }}
                
                // Wait for Discord's React to render
                setTimeout(fillDiscord, 1500);
            }})();
            """
            self.page().runJavaScript(fill_script)
    
    def _inject_standard_credentials(self, creds):
        """Standard credential injection for regular websites."""
        capture_script = """
        (function() {
            if (window._gbrowserCredCapture) return;
            window._gbrowserCredCapture = true;
            
            document.addEventListener('submit', function(e) {
                try {
                    var form = e.target;
                    if (form.tagName !== 'FORM') return;
                    var pass = form.querySelector('input[type="password"]');
                    if (!pass || !pass.value) return;
                    var user = form.querySelector('input[type="email"], input[type="text"]');
                    if (user && user.value) {
                        window._gbrowserCreds = {username: user.value, password: pass.value};
                    }
                } catch(e) {}
            }, true);
        })();
        """
        self.page().runJavaScript(capture_script)
        
        # Schedule credential check
        if self._cred_check_timer:
            self._cred_check_timer.stop()
        self._cred_check_timer = QTimer()
        self._cred_check_timer.setSingleShot(True)
        self._cred_check_timer.timeout.connect(lambda: self._check_and_save_credentials())
        self._cred_check_timer.start(2000)
        
        # Auto-fill if we have credentials
        if creds:
            username = creds["username"].replace("\\", "\\\\").replace("'", "\\'").replace("\n", "")
            password = creds["password"].replace("\\", "\\\\").replace("'", "\\'").replace("\n", "")
            
            fill_script = f"""
            (function() {{
                try {{
                    var pass = document.querySelector('input[type="password"]');
                    if (!pass) return;
                    var user = document.querySelector('input[type="email"], input[type="text"]');
                    if (user) {{
                        user.value = '{username}';
                        user.dispatchEvent(new Event('input', {{bubbles: true}}));
                    }}
                    pass.value = '{password}';
                    pass.dispatchEvent(new Event('input', {{bubbles: true}}));
                }} catch(e) {{}}
            }})();
            """
            self.page().runJavaScript(fill_script)
    
    def _check_and_save_credentials(self):
        if not self._browser:
            return
        
        def handle_result(result):
            if result and isinstance(result, dict):
                username = result.get("username", "")
                password = result.get("password", "")
                if username and password:
                    domain = self._browser.credentials_manager.get_domain_from_url(self.url().toString())
                    self._browser.credentials_manager.save_credentials(domain, username, password)
        
        self.page().runJavaScript("window._gbrowserCreds || null", handle_result)


class Browser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gorstak's Browser")
        self.setMinimumSize(800, 600)
        self.setWindowFlags(Qt.WindowType.Window)

        self.config = self._load_config()
        self.bookmarks = self.config.get("bookmarks", [])
        
        self.credentials_manager = CredentialsManager()
        
        geom = self.config.get("geometry", {})
        self.setGeometry(
            geom.get("x", 100),
            geom.get("y", 100),
            geom.get("width", 1280),
            geom.get("height", 820)
        )
        if geom.get("maximized", False):
            self.showMaximized()

        central = QWidget()
        central.setStyleSheet("background:#1e1e1e;")
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        nav = QWidget()
        nav.setFixedHeight(64)
        nav.setStyleSheet("background:#252526;")
        nlay = QHBoxLayout(nav)
        nlay.setContentsMargins(12, 8, 12, 8)
        nlay.setSpacing(12)

        self.profile = QWebEngineProfile("GBrowser", self)
        self.profile.setPersistentStoragePath(os.path.join(CONFIG_DIR, "storage"))
        self.profile.setCachePath(os.path.join(CONFIG_DIR, "cache"))
        self.profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies)
        
        self.ad_blocker = AdBlocker(self)
        self.profile.setUrlRequestInterceptor(self.ad_blocker)
        
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self._on_tab_changed)
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 0; }
            QTabBar::tab {
                background: #2d2d2d;
                color: #ccc;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                min-width: 120px;
                max-width: 200px;
            }
            QTabBar::tab:selected {
                background: #3c3c3c;
                color: white;
            }
            QTabBar::tab:hover:!selected {
                background: #353535;
            }
            QTabBar::close-button {
                image: none;
                subcontrol-position: right;
            }
        """)
        
        last_url = self.config.get("last_url", "https://www.google.com")
        self._add_tab(last_url)

        back_svg = '<svg width="24" height="24"><path d="M20 11 H7.83 l5.59-5.59 L12 4 l-8 8 8 8 1.41-1.41 L7.83 13 H20 v-2 z" fill="#ccc"/></svg>'
        forward_svg = '<svg width="24" height="24"><path d="M12 4 l-1.41 1.41 L16.17 11 H4 v2 h12.17 l-5.58 5.59 L12 20 l8-8 z" fill="#ccc"/></svg>'
        reload_svg = '<svg width="24" height="24"><path d="M17.65 6.35 C16.2 4.9 14.21 4 12 4 c-4.42 0-7.99 3.58-7.99 8 s3.57 8 7.99 8 c3.73 0 6.84-2.55 7.73-6 h-2.08 c-.82 2.33-3.04 4-5.65 4 -3.31 0-6-2.69-6-6 s2.69-6 6-6 c1.66 0 3.14.69 4.22 1.78 L13 11 h7 V4 l-2.35 2.35 z" fill="#ccc"/></svg>'
        home_svg = '<svg width="24" height="24"><path d="M10 20 v-6 h4 v6 h5 v-8 h3 L12 3 2 12 h3 v8 z" fill="#ccc"/></svg>'

        for svg, func in zip([back_svg, forward_svg, reload_svg, home_svg],
                             [self._go_back, self._go_forward, self._reload,
                              lambda: self._current_browser().setUrl(QUrl("https://www.google.com"))]):
            btn = QPushButton()
            btn.setFixedSize(48, 48)
            btn.setIcon(svg_icon(svg))
            btn.setIconSize(QSize(24, 24))
            btn.setStyleSheet("""
                QPushButton { background:#3c3c3c; border-radius:24px; }
                QPushButton:hover { background:#505050; }
                QPushButton:pressed { background:#606060; }
            """)
            btn.clicked.connect(func)
            nlay.addWidget(btn)

        new_tab_btn = QPushButton()
        new_tab_btn.setFixedSize(48, 48)
        new_tab_btn.setIcon(svg_icon(NEW_TAB_SVG))
        new_tab_btn.setIconSize(QSize(24, 24))
        new_tab_btn.setStyleSheet("""
            QPushButton { background:#3c3c3c; border-radius:24px; }
            QPushButton:hover { background:#505050; }
            QPushButton:pressed { background:#606060; }
        """)
        new_tab_btn.setToolTip("New Tab")
        new_tab_btn.clicked.connect(lambda: self._add_tab("https://www.google.com"))
        nlay.addWidget(new_tab_btn)

        # Bookmarks import button (B)
        self.btnB = QPushButton("B")
        self.btnB.setFixedSize(48, 48)
        self.btnB.setStyleSheet("""
            QPushButton { background:#3c3c3c; color:white; border-radius:24px; font-size:18px; }
            QPushButton:hover { background:#505050; }
            QPushButton:pressed { background:#606060; }
        """)
        self.btnB.clicked.connect(self.open_bookmarks_file)
        nlay.addWidget(self.btnB)

        # URL bar
        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("Search or enter address")
        self.url_bar.setFont(QFont("Segoe UI", 11))
        self.url_bar.setStyleSheet("""
            QLineEdit { background:#3c3c3c; color:white; border-radius:26px;
                        padding: 0px 20px; min-height: 44px; }
            QLineEdit:focus { background:#454545; border: 2px solid #0a84ff; padding: 0px 18px; }
        """)
        self.url_bar.returnPressed.connect(self.navigate)

        url_container = QWidget()
        url_container.setStyleSheet("background:#3c3c3c; border-radius:26px;")
        url_container.setFixedHeight(52)
        url_lay = QHBoxLayout(url_container)
        url_lay.setContentsMargins(0, 0, 0, 0)
        url_lay.addWidget(self.url_bar)
        nlay.addWidget(url_container, 1)

        self.profile.downloadRequested.connect(self.handle_download)

        layout.addWidget(nav)

        # Bookmarks bar
        self.bookmarks_bar_widget = QWidget()
        self.bookmarks_bar_widget.setFixedHeight(48)
        self.bookmarks_bar_widget.setStyleSheet("background:#2d2d2d;")
        bb_layout = QHBoxLayout(self.bookmarks_bar_widget)
        bb_layout.setContentsMargins(8, 6, 8, 6)
        bb_layout.setSpacing(6)

        self.bookmarks_container = QWidget()
        self.bookmarks_container_layout = QHBoxLayout(self.bookmarks_container)
        self.bookmarks_container_layout.setContentsMargins(0, 0, 0, 0)
        self.bookmarks_container_layout.setSpacing(6)
        bb_layout.addWidget(self.bookmarks_container)

        self.overflow_btn = QPushButton()
        self.overflow_btn.setFixedSize(32, 32)
        self.overflow_btn.setIcon(svg_icon(OVERFLOW_SVG))
        self.overflow_btn.setStyleSheet("""
            QPushButton { background:#3c3c3c; border-radius:16px; }
            QPushButton:hover { background:#505050; }
        """)
        self.overflow_btn.setVisible(False)
        self.overflow_btn.clicked.connect(self.show_overflow_menu)
        bb_layout.addWidget(self.overflow_btn)

        layout.addWidget(self.bookmarks_bar_widget)
        layout.addWidget(self.tabs, 1)

        # internal data
        self.overflow_items = []
        self._overflow_timer = QTimer()
        self._overflow_timer.setSingleShot(True)
        self._overflow_timer.timeout.connect(self._evaluate_overflow)
        self.resizeEvent = self._on_resize_override
        
        saved_bookmarks = self.config.get("bookmarks", [])
        if saved_bookmarks:
            self.bookmarks = saved_bookmarks
            self._rebuild_bookmarks_bar()

    def _add_tab(self, url="https://www.google.com"):
        tab = BrowserTab(self.profile, self, url)
        tab.titleChanged.connect(lambda title, t=tab: self._update_tab_title(t, title))
        tab.urlChanged.connect(lambda url, t=tab: self._update_url_bar(t, url))
        idx = self.tabs.addTab(tab, "New Tab")
        self.tabs.setCurrentIndex(idx)
        return tab
    
    def create_new_tab(self, url=None):
        """Called by CustomWebPage.createWindow for target=_blank links"""
        tab = BrowserTab(self.profile, self, url)
        tab.titleChanged.connect(lambda title, t=tab: self._update_tab_title(t, title))
        tab.urlChanged.connect(lambda url, t=tab: self._update_url_bar(t, url))
        idx = self.tabs.addTab(tab, "New Tab")
        self.tabs.setCurrentIndex(idx)
        return tab.page()
    
    def close_tab(self, index):
        if self.tabs.count() > 1:
            widget = self.tabs.widget(index)
            self.tabs.removeTab(index)
            widget.deleteLater()
        else:
            # Last tab - close window
            self.close()
    
    def _update_tab_title(self, tab, title):
        idx = self.tabs.indexOf(tab)
        if idx >= 0:
            short_title = title[:25] + "..." if len(title) > 25 else title
            self.tabs.setTabText(idx, short_title or "New Tab")
    
    def _update_url_bar(self, tab, url):
        if tab == self._current_browser():
            self.url_bar.setText(url.toString())
    
    def _on_tab_changed(self, index):
        if not hasattr(self, 'url_bar'):
            return
        browser = self._current_browser()
        if browser:
            self.url_bar.setText(browser.url().toString())
    
    def _current_browser(self):
        return self.tabs.currentWidget()
    
    def _go_back(self):
        b = self._current_browser()
        if b:
            b.back()
    
    def _go_forward(self):
        b = self._current_browser()
        if b:
            b.forward()
    
    def _reload(self):
        b = self._current_browser()
        if b:
            b.reload()

    def _load_config(self):
        """Load config from file"""
        if not os.path.exists(CONFIG_FILE):
            return {}
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    
    def _save_config(self):
        """Save config to file"""
        os.makedirs(CONFIG_DIR, exist_ok=True)
        
        geom = self.geometry()
        self.config["geometry"] = {
            "x": geom.x(),
            "y": geom.y(),
            "width": geom.width(),
            "height": geom.height(),
            "maximized": self.isMaximized()
        }
        
        browser = self._current_browser()
        if browser:
            self.config["last_url"] = browser.url().toString()
        self.config["bookmarks"] = self.bookmarks
        
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Failed to save config: {e}")
    
    # ------------------------
    # Bookmarks file handling
    # ------------------------
    def open_bookmarks_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Bookmarks HTML", "", "HTML Files (*.html *.htm);;All Files (*)")
        if not file_path:
            return
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                html = f.read()
            self._parse_bookmarks_html(html)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open bookmarks file:\n{e}")

    def _parse_bookmarks_html(self, html):
        try:
            soup = BeautifulSoup(html, "html5lib")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")
        
        def parse_dl(dl_tag, depth=0):
            """Robust recursive parser for Netscape-style bookmarks HTML."""
            nodes = []
            
            all_dts = dl_tag.find_all("dt")
            direct_dts = []
            for dt in all_dts:
                parent = dt.parent
                while parent and parent.name != "dl":
                    parent = parent.parent
                if parent is dl_tag:
                    direct_dts.append(dt)
            
            for dt in direct_dts:
                a = dt.find("a", recursive=False) or dt.find("a")
                h3 = dt.find(["h3", "h1", "h2"], recursive=False) or dt.find(["h3", "h1", "h2"])

                if a and h3:
                    elem_str = str(dt)
                    h3_pos = elem_str.find(str(h3))
                    a_pos = elem_str.find(str(a))
                    if h3_pos < a_pos:
                        a = None
                    else:
                        h3 = None

                if a and not h3:
                    title = (a.get_text(strip=True) or a.get("href") or "").strip()
                    href = a.get("href")
                    if href:
                        nodes.append({"type": "link", "title": title or href, "href": href})
                    continue

                if h3:
                    folder_title = (h3.get_text(strip=True) or "Folder").strip()
                    children = []

                    sibling = dt.next_sibling
                    while sibling:
                        if hasattr(sibling, 'name'):
                            if sibling.name == "dl":
                                children = parse_dl(sibling, depth + 1)
                                break
                            elif sibling.name == "dt":
                                break
                        sibling = sibling.next_sibling
                    
                    if not children:
                        child_dl = dt.find("dl")
                        if child_dl:
                            children = parse_dl(child_dl, depth + 1)
                    
                    nodes.append({"type": "folder", "title": folder_title, "children": children})

            return nodes

        top_dl = soup.find("dl")
        if top_dl:
            parsed = parse_dl(top_dl)
            if len(parsed) == 1 and parsed[0].get("type") == "folder":
                parsed = parsed[0].get("children", parsed)
        else:
            parsed = []
            for a in soup.find_all("a"):
                href = a.get("href")
                if href:
                    parsed.append({
                        "type": "link",
                        "title": (a.get_text(strip=True) or href).strip(),
                        "href": href
                    })

        self.bookmarks = parsed
        self._rebuild_bookmarks_bar()

    # ------------------------
    # Build bookmarks bar UI
    # ------------------------
    def _clear_bookmarks_container(self):
        while self.bookmarks_container_layout.count():
            item = self.bookmarks_container_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def _rebuild_bookmarks_bar(self):
        self._clear_bookmarks_container()
        self.overflow_items = []

        if not self.bookmarks:
            label = QLabel("No bookmarks loaded")
            label.setStyleSheet("color: #666; padding: 6px 10px;")
            self.bookmarks_container_layout.addWidget(label)
            spacer = QWidget()
            spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            self.bookmarks_container_layout.addWidget(spacer)
            return

        for node in self.bookmarks:
            if node["type"] == "link":
                btn = QPushButton(node.get("title", node.get("href", "untitled")))
                btn.setCursor(Qt.CursorShape.PointingHandCursor)
                btn.setProperty("href", node.get("href"))
                btn.setStyleSheet("""
                    QPushButton { background:#3c3c3c; color:white; border-radius:6px; padding:6px 10px; }
                    QPushButton:hover { background:#505050; }
                """)
                btn.clicked.connect(lambda checked, h=node.get("href"): self._open_href(h))
                self.bookmarks_container_layout.addWidget(btn)
            elif node["type"] == "folder":
                tb = QToolButton()
                tb.setText(node.get("title", "Folder"))
                tb.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
                tb.setStyleSheet("""
                    QToolButton { background:#3c3c3c; color:white; border-radius:6px; padding:6px 10px; }
                    QToolButton:hover { background:#505050; }
                """)
                menu = QMenu()

                def add_children(m, children):
                    for c in children:
                        if c["type"] == "link":
                            a = QAction(c.get("title", c.get("href")), self)
                            href = c.get("href")
                            a.triggered.connect(lambda checked, h=href: self._open_href(h))
                            m.addAction(a)
                        elif c["type"] == "folder":
                            sub = QMenu(c.get("title", "Folder"), self)
                            add_children(sub, c.get("children", []))
                            m.addMenu(sub)

                add_children(menu, node.get("children", []))
                tb.setMenu(menu)
                self.bookmarks_container_layout.addWidget(tb)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.bookmarks_container_layout.addWidget(spacer)
        self._overflow_timer.start(120)

    def _open_href(self, href):
        if not href:
            return
        if href.startswith("javascript:") or href.startswith("data:"):
            QMessageBox.information(self, "Unsupported", "Bookmark uses a javascript/data URL which cannot be opened.")
            return
        if not href.startswith(("http://", "https://")):
            href = "https://" + href
        # Open in new tab
        self._add_tab(href)

    # ------------------------
    # Overflow
    # ------------------------
    def _on_resize_override(self, event):
        QMainWindow.resizeEvent(self, event)
        self._overflow_timer.start(120)

    def _evaluate_overflow(self):
        available = self.bookmarks_bar_widget.width() - 80
        total = 0
        widgets = []

        for i in range(self.bookmarks_container_layout.count()):
            it = self.bookmarks_container_layout.itemAt(i)
            w = it.widget()
            if w is None:
                continue
            if isinstance(w, QWidget) and w.sizePolicy().horizontalPolicy() == QSizePolicy.Policy.Expanding:
                break
            w.adjustSize()
            w_w = w.width() if w.width() > 0 else w.sizeHint().width()
            widgets.append((w, w_w))
            total += w_w + self.bookmarks_container_layout.spacing()

        if total <= available:
            for w, _ in widgets:
                w.setVisible(True)
            self.overflow_items = []
            self.overflow_btn.setVisible(False)
            return

        used = 0
        shown = []
        overflow = []
        for w, w_w in widgets:
            if used + w_w + self.bookmarks_container_layout.spacing() <= available:
                shown.append(w)
                used += w_w + self.bookmarks_container_layout.spacing()
            else:
                overflow.append(w)

        for w, _ in widgets:
            w.setVisible(w in shown)

        self.overflow_items = []
        for w in overflow:
            if isinstance(w, QToolButton):
                self.overflow_items.append({"type": "folder", "title": w.text(), "menu": w.menu()})
            elif isinstance(w, QPushButton):
                self.overflow_items.append({"type": "link", "title": w.text(), "href": w.property("href")})

        self.overflow_btn.setVisible(bool(self.overflow_items))

    def show_overflow_menu(self):
        if not self.overflow_items:
            return
        menu = QMenu()
        for it in self.overflow_items:
            if it["type"] == "link":
                act = QAction(it["title"], self)
                h = it.get("href")
                act.triggered.connect(lambda checked, href=h: self._open_href(href))
                menu.addAction(act)
            elif it["type"] == "folder":
                sub = QMenu(it["title"], self)
                src_menu = it.get("menu")

                def clone_menu(src, dst):
                    for a in src.actions():
                        if a.menu():
                            child = QMenu(a.text(), self)
                            clone_menu(a.menu(), child)
                            dst.addMenu(child)
                        else:
                            new = QAction(a.text(), self)
                            new.triggered.connect(lambda checked, t=a.text(): self._open_href(self._find_href_by_title(t)))
                            dst.addAction(new)

                if src_menu:
                    clone_menu(src_menu, sub)
                menu.addMenu(sub)
        menu.exec(self.overflow_btn.mapToGlobal(self.overflow_btn.rect().bottomLeft()))

    def _find_href_by_title(self, title):
        queue = list(self.bookmarks)
        while queue:
            node = queue.pop(0)
            if node["type"] == "link" and node.get("title") == title:
                return node.get("href")
            if node["type"] == "folder":
                queue = node.get("children", []) + queue
        return ""

    # ------------------------
    # Navigation & downloads
    # ------------------------
    def navigate(self):
        url = self.url_bar.text().strip()
        if not url:
            return
        if " " in url and "." not in url:
            url = "https://www.google.com/search?q=" + url.replace(" ", "+")
        elif not url.startswith(("http://", "https://")):
            url = "https://" + url
        browser = self._current_browser()
        if browser:
            browser.setUrl(QUrl(url))

    def handle_download(self, item):
        path, _ = QFileDialog.getSaveFileName(self, "Save File", item.suggestedFileName())
        if path:
            item.setDownloadDirectory(os.path.dirname(path))
            item.setDownloadFileName(os.path.basename(path))
            item.accept()

    def closeEvent(self, event):
        self._save_config()
        
        # Close all tabs
        for i in range(self.tabs.count()):
            widget = self.tabs.widget(i)
            if widget:
                widget.stop()
                widget.load(QUrl("about:blank"))
        
        super().closeEvent(event)


class DLLProtection:
    """Monitors and removes injected DLLs (scans every 5 seconds)"""
    
    def __init__(self):
        self.running = False
        self.thread = None
        self.initial_dlls = set()
        
        # Whitelist patterns for legitimate lazy-loaded DLLs
        self.whitelist_patterns = [
            'python', 'pyqt6', 'qt6', 'site-packages',
            'windows\\system32', 'windows\\syswow64', 'windows\\winsxs',
            'nvidia', 'amd', 'intel', 'program files\\common files\\microsoft',
            'microsoft shared', 'vcruntime', 'msvcp', 'ucrtbase',
            'directx', 'dotnet', 'windows defender', 'dwmapi',
            'uxtheme', 'comctl32', 'comdlg32', 'shell32', 'ole32',
            'tiptsf', 'msctf', 'imm32', 'textinputframework',
        ]
    
    def _get_loaded_dlls(self):
        """Get set of currently loaded DLL paths"""
        try:
            import ctypes
            from ctypes import wintypes
            
            psapi = ctypes.WinDLL('psapi')
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            
            # Set up function signatures
            psapi.EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
            psapi.EnumProcessModules.restype = wintypes.BOOL
            psapi.GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
            psapi.GetModuleFileNameExW.restype = wintypes.DWORD
            kernel32.GetCurrentProcess.argtypes = []
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            
            h_process = kernel32.GetCurrentProcess()
            h_modules = (wintypes.HMODULE * 1024)()
            cb_needed = wintypes.DWORD()
            
            dlls = set()
            if psapi.EnumProcessModules(h_process, h_modules, ctypes.sizeof(h_modules), ctypes.byref(cb_needed)):
                count = cb_needed.value // ctypes.sizeof(wintypes.HMODULE)
                for i in range(count):
                    if h_modules[i]:
                        path_buf = ctypes.create_unicode_buffer(512)
                        if psapi.GetModuleFileNameExW(h_process, h_modules[i], path_buf, 512):
                            dlls.add(path_buf.value.lower())
            return dlls
        except Exception as e:
            print(f"[DLL Protection] Error enumerating DLLs: {e}")
            return set()
    
    def _is_whitelisted(self, dll_path):
        """Check if DLL is in whitelist"""
        path_lower = dll_path.lower()
        return any(pattern in path_lower for pattern in self.whitelist_patterns)
    
    def _remove_dll(self, dll_path):
        """Attempt to unload a DLL"""
        try:
            import ctypes
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            h_module = kernel32.GetModuleHandleW(dll_path)
            if h_module:
                for _ in range(10):
                    if not kernel32.FreeLibrary(h_module):
                        break
                return True
        except:
            pass
        return False
    
    def _monitor_loop(self):
        """Main monitoring loop - runs every 5 seconds"""
        while self.running:
            try:
                current_dlls = self._get_loaded_dlls()
                new_dlls = current_dlls - self.initial_dlls
                
                for dll in new_dlls:
                    if not self._is_whitelisted(dll):
                        print(f"[DLL Protection] DETECTED: {dll}")
                        if self._remove_dll(dll):
                            print(f"[DLL Protection] REMOVED: {dll}")
                        else:
                            print(f"[DLL Protection] Failed to remove: {dll}")
                    else:
                        # Add whitelisted DLLs to initial set so we don't check them again
                        self.initial_dlls.add(dll)
            except Exception as e:
                print(f"[DLL Protection] Monitor error: {e}")
            
            # Sleep for 5 seconds instead of 50ms
            import time
            time.sleep(5.0)
    
    def start(self):
        """Start DLL protection"""
        if self.running:
            return
        
        self.initial_dlls = self._get_loaded_dlls()
        print(f"[DLL Protection] Captured {len(self.initial_dlls)} baseline DLLs")
        
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        print("[DLL Protection] Monitoring started (5-second interval)")
    
    def stop(self):
        """Stop DLL protection"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
        print("[DLL Protection] Stopped")


class CredentialsManager:
    """Secure credentials storage using Windows DPAPI"""
    
    def __init__(self):
        self.credentials = {}
        self._load()
    
    def _encrypt(self, text):
        """Encrypt using Windows DPAPI (Data Protection API)"""
        if sys.platform != 'win32':
            # Fallback for non-Windows - use base64 only (not secure, but functional)
            import base64
            return base64.b64encode(text.encode('utf-8')).decode('ascii')
        
        try:
            import base64
            
            # DPAPI structures
            class DATA_BLOB(ctypes.Structure):
                _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
            
            crypt32 = ctypes.WinDLL('crypt32', use_last_error=True)
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            
            CryptProtectData = crypt32.CryptProtectData
            CryptProtectData.argtypes = [
                ctypes.POINTER(DATA_BLOB),  # pDataIn
                wintypes.LPCWSTR,           # szDataDescr
                ctypes.POINTER(DATA_BLOB),  # pOptionalEntropy
                ctypes.c_void_p,            # pvReserved
                ctypes.c_void_p,            # pPromptStruct
                wintypes.DWORD,             # dwFlags
                ctypes.POINTER(DATA_BLOB)   # pDataOut
            ]
            CryptProtectData.restype = wintypes.BOOL
            
            # Prepare input
            data = text.encode('utf-8')
            data_in = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data, len(data)), ctypes.POINTER(ctypes.c_char)))
            data_out = DATA_BLOB()
            
            # Encrypt with DPAPI (CRYPTPROTECT_LOCAL_MACHINE = 0x4 for machine-level, 0 for user-level)
            if CryptProtectData(ctypes.byref(data_in), None, None, None, None, 0, ctypes.byref(data_out)):
                encrypted = ctypes.string_at(data_out.pbData, data_out.cbData)
                kernel32.LocalFree(data_out.pbData)
                return base64.b64encode(encrypted).decode('ascii')
            else:
                raise ctypes.WinError(ctypes.get_last_error())
                
        except Exception as e:
            print(f"[Credentials] DPAPI encrypt failed: {e}, using fallback")
            import base64
            return base64.b64encode(text.encode('utf-8')).decode('ascii')
    
    def _decrypt(self, text):
        """Decrypt using Windows DPAPI"""
        if sys.platform != 'win32':
            import base64
            return base64.b64decode(text.encode('ascii')).decode('utf-8')
        
        try:
            import base64
            
            class DATA_BLOB(ctypes.Structure):
                _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
            
            crypt32 = ctypes.WinDLL('crypt32', use_last_error=True)
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            
            CryptUnprotectData = crypt32.CryptUnprotectData
            CryptUnprotectData.argtypes = [
                ctypes.POINTER(DATA_BLOB),
                ctypes.POINTER(wintypes.LPWSTR),
                ctypes.POINTER(DATA_BLOB),
                ctypes.c_void_p,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(DATA_BLOB)
            ]
            CryptUnprotectData.restype = wintypes.BOOL
            
            # Prepare input
            encrypted = base64.b64decode(text.encode('ascii'))
            data_in = DATA_BLOB(len(encrypted), ctypes.cast(ctypes.create_string_buffer(encrypted, len(encrypted)), ctypes.POINTER(ctypes.c_char)))
            data_out = DATA_BLOB()
            
            # Decrypt
            if CryptUnprotectData(ctypes.byref(data_in), None, None, None, None, 0, ctypes.byref(data_out)):
                decrypted = ctypes.string_at(data_out.pbData, data_out.cbData).decode('utf-8')
                kernel32.LocalFree(data_out.pbData)
                return decrypted
            else:
                raise ctypes.WinError(ctypes.get_last_error())
                
        except Exception as e:
            print(f"[Credentials] DPAPI decrypt failed: {e}, trying fallback")
            try:
                import base64
                return base64.b64decode(text.encode('ascii')).decode('utf-8')
            except:
                return ""
    
    def _load(self):
        """Load credentials from file"""
        if not os.path.exists(CREDENTIALS_FILE):
            return
        try:
            with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                for domain, creds in data.items():
                    self.credentials[domain] = {
                        'username': self._decrypt(creds['username']),
                        'password': self._decrypt(creds['password'])
                    }
        except Exception as e:
            print(f"[Credentials] Failed to load: {e}")
    
    def _save(self):
        """Save credentials to file"""
        os.makedirs(CONFIG_DIR, exist_ok=True)
        try:
            data = {}
            for domain, creds in self.credentials.items():
                data[domain] = {
                    'username': self._encrypt(creds['username']),
                    'password': self._encrypt(creds['password'])
                }
            with open(CREDENTIALS_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[Credentials] Failed to save: {e}")
    
    def save_credentials(self, domain, username, password):
        """Save credentials for a domain"""
        if username and password:
            self.credentials[domain] = {'username': username, 'password': password}
            self._save()
            print(f"[Credentials] Saved for {domain}")
    
    def get_credentials(self, domain):
        """Get credentials for a domain"""
        return self.credentials.get(domain)
    
    def get_domain_from_url(self, url):
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc.lower()




if __name__ == "__main__":
    print("[DEBUG] Starting...")
    try:
        
        print("[DEBUG] Creating QApplication...")
        app = QApplication(sys.argv)
        print("[DEBUG] QApplication created")
        app.setApplicationName("Gorstak's Browser")
        print("[DEBUG] Creating Browser window...")
        win = Browser()
        print("[DEBUG] Browser created, showing...")
        win.show()
        
        dll_protection = DLLProtection()
        QTimer.singleShot(2000, dll_protection.start)  # Start after 2 seconds
        
        print("[DEBUG] Entering event loop...")
        exit_code = app.exec()
        
        dll_protection.stop()
        
        sys.exit(exit_code)
    except Exception as e:
        print(f"ERROR: {e}")
        traceback.print_exc()
        input("Press Enter to exit...")
