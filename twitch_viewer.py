import base64
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import ssl
import ctypes
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from PyQt6.QtCore import Qt, QUrl, QProcess, pyqtSignal, QObject, QCoreApplication
from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QLabel,
    QSplitter,
    QMessageBox,
    QComboBox,
    QFrame,
    QCheckBox,
    QListWidget,
    QListWidgetItem,
    QTabWidget,
    QGroupBox,
    QFormLayout,
    QSizePolicy,
    QSlider,
)

QCoreApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts, True)

from PyQt6.QtWebEngineCore import QWebEngineProfile, QWebEngineSettings, QWebEnginePage
from PyQt6.QtWebEngineWidgets import QWebEngineView


APP_TITLE = "Twitch Viewer"
SETTINGS_FILE = "twitch_viewer_settings.json"
TOKEN_FILE = "twitch_token.json"

REDIRECT_HOST = "127.0.0.1"
REDIRECT_PORT = 17563
REDIRECT_URI = f"https://{REDIRECT_HOST}:{REDIRECT_PORT}/callback"

SCOPES = ["user:read:follows"]

QUALITY_OPTIONS = [
    "best",
    "1080p60",
    "1080p",
    "720p60",
    "720p",
    "480p",
    "360p",
    "160p",
    "worst",
]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = os.path.join(BASE_DIR, "oauth_cert")
CERT_PEM = os.path.join(CERT_DIR, "cert.pem")
KEY_PEM = os.path.join(CERT_DIR, "key.pem")
CERT_CER = os.path.join(CERT_DIR, "cert.cer")

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

MPV_IPC_PATH = r"\\.\pipe\twitch_viewer_mpv_ipc"


def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def delete_file(path):
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def normalize_channel(value: str) -> str:
    v = (value or "").strip().lower()
    v = v.replace("https://", "").replace("http://", "")
    v = v.replace("www.", "")
    v = v.replace("m.twitch.tv/", "twitch.tv/")
    if v.startswith("twitch.tv/"):
        v = v[len("twitch.tv/"):]
    v = v.split("?")[0].split("#")[0].strip("/")
    if "/" in v:
        v = v.split("/")[0]
    v = "".join(ch for ch in v if ch.isalnum() or ch == "_")
    return v


def find_executable(name: str):
    return shutil.which(name)


def find_mpv_path():
    mpv_exe = os.path.join(BASE_DIR, "mpv.exe")
    if os.path.exists(mpv_exe):
        return mpv_exe
    return find_executable("mpv")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def pkce_pair():
    verifier = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode("utf-8")).digest())
    return verifier, challenge


def read_http_error(e: urllib.error.HTTPError):
    try:
        raw = e.read()
    except Exception:
        raw = b""
    try:
        txt = raw.decode("utf-8", errors="ignore")
    except Exception:
        txt = ""
    try:
        js = json.loads(txt)
        msg = js.get("message") or js.get("error_description") or js.get("error") or txt
        return f"{e.code} {e.reason}: {msg}"
    except Exception:
        if txt.strip():
            return f"{e.code} {e.reason}: {txt.strip()}"
        return f"{e.code} {e.reason}"


def http_json(url: str, method="GET", headers=None, data=None, timeout=30):
    h = {"User-Agent": "Mozilla/5.0"}
    if headers:
        h.update(headers)
    if data is not None and not isinstance(data, (bytes, bytearray)):
        data = data.encode("utf-8")
    req = urllib.request.Request(url, method=method, headers=h, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(read_http_error(e))
    except Exception as e:
        raise RuntimeError(str(e))
    try:
        return json.loads(body.decode("utf-8", errors="ignore"))
    except Exception:
        raise RuntimeError("Response was not JSON")


def form_post(url: str, fields: dict, headers=None, timeout=30):
    payload = urllib.parse.urlencode(fields).encode("utf-8")
    h = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, method="POST", headers=h, data=payload)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(read_http_error(e))
    except Exception as e:
        raise RuntimeError(str(e))
    try:
        return json.loads(body.decode("utf-8", errors="ignore"))
    except Exception:
        raise RuntimeError("Token response was not JSON")


def streamlink_stream_url(channel: str, quality: str):
    cmd = [
        "streamlink",
        "--twitch-disable-ads",
        "--twitch-low-latency",
        "--stream-url",
        f"https://www.twitch.tv/{channel}",
        quality,
    ]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        err = (p.stderr or "").strip()
        out = (p.stdout or "").strip()
        msg = err if err else out
        raise RuntimeError(msg if msg else "Streamlink failed")
    url = (p.stdout or "").strip()
    if not url.startswith("https://") and not url.startswith("http://"):
        raise RuntimeError("Streamlink returned an invalid URL")
    return url


def ensure_cert_dir():
    os.makedirs(CERT_DIR, exist_ok=True)


def ensure_cryptography_installed():
    try:
        import cryptography  # noqa: F401
        return True
    except Exception:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
            return True
        except Exception:
            return False


def create_https_certificate():
    if not ensure_cryptography_installed():
        raise RuntimeError("cryptography install failed")

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime
    import ipaddress

    ensure_cert_dir()

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local OAuth"),
            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
        ]
    )

    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.DNSName("127.0.0.1"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    with open(KEY_PEM, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(CERT_PEM, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(CERT_CER, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))


def run_powershell_admin(command: str):
    ps = "powershell.exe"
    args = f'-NoProfile -ExecutionPolicy Bypass -Command "{command}"'
    r = ctypes.windll.shell32.ShellExecuteW(None, "runas", ps, args, None, 1)
    return r > 32


def install_cert_admin():
    ensure_cert_dir()
    if not os.path.exists(CERT_CER):
        raise RuntimeError("cert.cer not found")
    cmd = f'certutil -addstore -f Root "{CERT_CER}"'
    ok = run_powershell_admin(cmd)
    if not ok:
        raise RuntimeError("Admin launch failed")


def have_https_cert_files():
    return os.path.exists(CERT_PEM) and os.path.exists(KEY_PEM) and os.path.exists(CERT_CER)


def make_ssl_context():
    if not have_https_cert_files():
        raise RuntimeError("HTTPS certificate files missing")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_PEM, KEY_PEM)
    return ctx


def mpv_ipc_send(command_obj: dict, timeout_seconds=0.15):
    payload = (json.dumps(command_obj, ensure_ascii=False) + "\n").encode("utf-8")
    end_at = time.time() + timeout_seconds
    last_err = None
    while time.time() < end_at:
        try:
            with open(MPV_IPC_PATH, "wb", buffering=0) as f:
                f.write(payload)
            return True
        except Exception as e:
            last_err = e
            time.sleep(0.03)
    raise RuntimeError(str(last_err) if last_err else "mpv ipc failed")


@dataclass
class FollowedChannel:
    broadcaster_id: str
    login: str
    display_name: str
    live: bool = False
    title: str = ""
    game_name: str = ""
    viewer_count: int = 0


class OAuthBus(QObject):
    code_received = pyqtSignal(str, str)


class OAuthHandler(BaseHTTPRequestHandler):
    bus = None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/callback":
            self.send_response(404)
            self.end_headers()
            return

        qs = urllib.parse.parse_qs(parsed.query)
        code = (qs.get("code", [""]) or [""])[0]
        state = (qs.get("state", [""]) or [""])[0]

        ok = b"<html><body><h3>Authorization completed. You can close this window.</h3></body></html>"
        bad = b"<html><body><h3>Authorization failed. You can close this window.</h3></body></html>"

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        if code and state and OAuthHandler.bus is not None:
            self.wfile.write(ok)
            OAuthHandler.bus.code_received.emit(code, state)
        else:
            self.wfile.write(bad)

    def log_message(self, format, *args):
        return


class TwitchViewer(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1700, 940)

        self.settings = load_json(SETTINGS_FILE, {})
        self.token = load_json(TOKEN_FILE, None)

        self.client_id = (self.settings.get("client_id") or "").strip()
        self.last_quality = (self.settings.get("quality") or "best").strip()
        self.only_live_default = bool(self.settings.get("only_live", True))
        self.embed_default = bool(self.settings.get("embed_mpv", True))
        self.volume_default = int(self.settings.get("volume", 70) or 70)

        self.mpv_path = find_mpv_path()
        if not self.mpv_path:
            QMessageBox.critical(self, "Error", "mpv.exe not found. Put mpv.exe next to main.py.")
            raise SystemExit(1)

        if not find_executable("streamlink"):
            QMessageBox.critical(self, "Error", "streamlink not found. Install with pip install streamlink")
            raise SystemExit(1)

        self.mpv_workdir = os.path.dirname(os.path.abspath(self.mpv_path))
        self.mpv_process = QProcess(self)
        self.mpv_process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)

        self.oauth_bus = OAuthBus()
        self.oauth_bus.code_received.connect(self.on_oauth_code)

        self.oauth_server = None
        self.oauth_thread = None
        self.pkce_verifier = None
        self.oauth_state = None

        self.user_id = None
        self.followed = []

        self.profile = QWebEngineProfile("twitch_profile", self)
        self.profile.setHttpUserAgent(CHROME_UA)
        profile_path = os.path.join(BASE_DIR, "web_profile")
        self.profile.setPersistentStoragePath(profile_path)
        self.profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies)

        self.chat_view = QWebEngineView()
        self.chat_page = QWebEnginePage(self.profile, self.chat_view)
        self.chat_view.setPage(self.chat_page)
        self.chat_view.settings().setAttribute(QWebEngineSettings.WebAttribute.PlaybackRequiresUserGesture, False)

        root = QVBoxLayout(self)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)

        self.status = QLabel("")
        self.status.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        root.addWidget(self.status)

        self.stream_tab_index = None
        self.follows_tab_index = None
        self.settings_tab_index = None

        self.build_stream_tab()
        self.build_follows_tab()
        self.build_settings_tab()

        self.bootstrap()

    def bootstrap(self):
        self.render_recent()
        if self.token_valid(self.token) and self.client_id:
            try:
                self.ensure_user_id()
                self.refresh_follows(silent=True)
                self.status.setText("Authorized")
            except Exception:
                self.status.setText("Not authorized")
        else:
            self.status.setText("Not authorized")

    def build_stream_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(header)

        self.channel_input = QLineEdit()
        self.channel_input.setPlaceholderText("Channel name or twitch.tv link")
        header_layout.addWidget(self.channel_input, 1)

        self.quality_box = QComboBox()
        self.quality_box.addItems(QUALITY_OPTIONS)
        if self.last_quality in QUALITY_OPTIONS:
            self.quality_box.setCurrentText(self.last_quality)
        header_layout.addWidget(self.quality_box)

        self.embed_toggle = QCheckBox("Embed video")
        self.embed_toggle.setChecked(self.embed_default)
        header_layout.addWidget(self.embed_toggle)

        vol_label = QLabel("Volume")
        header_layout.addWidget(vol_label)

        self.volume_slider = QSlider(Qt.Orientation.Horizontal)
        self.volume_slider.setMinimum(0)
        self.volume_slider.setMaximum(100)
        self.volume_slider.setValue(self.volume_default)
        self.volume_slider.setFixedWidth(160)
        self.volume_slider.valueChanged.connect(self.on_volume_changed)
        header_layout.addWidget(self.volume_slider)

        self.volume_value = QLabel(str(self.volume_default))
        self.volume_value.setFixedWidth(34)
        self.volume_value.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        header_layout.addWidget(self.volume_value)

        self.open_button = QPushButton("Open")
        self.open_button.clicked.connect(self.open_from_input)
        header_layout.addWidget(self.open_button)

        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_player)
        header_layout.addWidget(self.stop_button)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter, 1)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)

        recent_group = QGroupBox("Recent channels")
        recent_group.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
        recent_layout = QVBoxLayout(recent_group)

        self.recent_list = QListWidget()
        self.recent_list.itemClicked.connect(self.on_recent_clicked)
        recent_layout.addWidget(self.recent_list)

        left_layout.addWidget(recent_group, 1)

        center_panel = QWidget()
        center_layout = QVBoxLayout(center_panel)
        center_layout.setContentsMargins(0, 0, 0, 0)

        video_group = QGroupBox("Video")
        video_layout = QVBoxLayout(video_group)
        self.video_container = QFrame()
        self.video_container.setStyleSheet("background: black; border-radius: 12px;")
        video_layout.addWidget(self.video_container, 1)
        center_layout.addWidget(video_group, 1)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)

        chat_group = QGroupBox("Chat")
        chat_layout = QVBoxLayout(chat_group)
        chat_layout.addWidget(self.chat_view, 1)
        right_layout.addWidget(chat_group, 1)

        splitter.addWidget(left_panel)
        splitter.addWidget(center_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([320, 980, 420])

        self.stream_tab_index = self.tabs.addTab(page, "Stream")

    def build_follows_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        top = QHBoxLayout()
        layout.addLayout(top)

        self.authorize_button = QPushButton("Authorize in browser")
        self.authorize_button.clicked.connect(self.start_authorize)
        top.addWidget(self.authorize_button)

        self.clear_auth_button = QPushButton("Clear authorization")
        self.clear_auth_button.clicked.connect(self.clear_authorization)
        top.addWidget(self.clear_auth_button)

        self.refresh_follows_button = QPushButton("Refresh")
        self.refresh_follows_button.clicked.connect(lambda: self.refresh_follows(silent=False))
        top.addWidget(self.refresh_follows_button)

        self.only_live_toggle = QCheckBox("Only live")
        self.only_live_toggle.setChecked(self.only_live_default)
        self.only_live_toggle.stateChanged.connect(self.render_follow_list)
        top.addWidget(self.only_live_toggle)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter usernames")
        self.filter_input.textChanged.connect(self.render_follow_list)
        top.addWidget(self.filter_input, 1)

        self.follow_list = QListWidget()
        self.follow_list.itemClicked.connect(self.on_follow_clicked)
        layout.addWidget(self.follow_list, 1)

        hint = QLabel(f"Redirect URL: {REDIRECT_URI}")
        hint.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(hint)

        self.follows_tab_index = self.tabs.addTab(page, "Follows")

    def build_settings_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        api_box = QGroupBox("Twitch API")
        api_form = QFormLayout(api_box)

        self.client_id_input = QLineEdit()
        self.client_id_input.setPlaceholderText("Enter your Twitch Client ID")
        self.client_id_input.setText(self.client_id)
        api_form.addRow("Client ID", self.client_id_input)

        self.save_settings_button = QPushButton("Save settings")
        self.save_settings_button.clicked.connect(self.save_settings_from_ui)
        api_form.addRow("", self.save_settings_button)

        layout.addWidget(api_box)

        info_box = QGroupBox("How to get a Client ID")
        info_layout = QVBoxLayout(info_box)

        info_text = (
            "This application is a desktop app and uses a Public Twitch application.\n\n"
            "For Public applications Twitch does not provide a Client Secret.\n"
            "This is normal and intended.\n\n"
            "Steps\n"
            "1 Open the Twitch Developer Console\n"
            "2 Create an application\n"
            "3 Set Client Type to Public\n"
            "4 Add this Redirect URL exactly\n"
            f"{REDIRECT_URI}\n"
            "5 Copy the Client ID into this program\n\n"
            "If you see no Client Secret in the Twitch dashboard everything is correct."
        )
        self.public_info = QLabel(info_text)
        self.public_info.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        info_layout.addWidget(self.public_info)

        layout.addWidget(info_box)

        cert_box = QGroupBox("HTTPS callback certificate")
        cert_layout = QVBoxLayout(cert_box)

        self.cert_status = QLabel(self.get_cert_status_text())
        self.cert_status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        cert_layout.addWidget(self.cert_status)

        cert_buttons = QHBoxLayout()
        cert_layout.addLayout(cert_buttons)

        self.create_cert_button = QPushButton("Create HTTPS certificate")
        self.create_cert_button.clicked.connect(self.ui_create_cert)
        cert_buttons.addWidget(self.create_cert_button)

        self.install_cert_button = QPushButton("Install certificate to Windows Trusted Root")
        self.install_cert_button.clicked.connect(self.ui_install_cert)
        cert_buttons.addWidget(self.install_cert_button)

        self.open_cert_folder_button = QPushButton("Open certificate folder")
        self.open_cert_folder_button.clicked.connect(self.ui_open_cert_folder)
        cert_buttons.addWidget(self.open_cert_folder_button)

        layout.addWidget(cert_box)

        self.settings_tab_index = self.tabs.addTab(page, "Settings")

    def get_cert_status_text(self):
        os.makedirs(CERT_DIR, exist_ok=True)
        parts = []
        parts.append(f"Redirect URL: {REDIRECT_URI}")
        parts.append(f"cert.pem: {'OK' if os.path.exists(CERT_PEM) else 'Missing'}")
        parts.append(f"key.pem: {'OK' if os.path.exists(KEY_PEM) else 'Missing'}")
        parts.append(f"cert.cer: {'OK' if os.path.exists(CERT_CER) else 'Missing'}")
        parts.append(f"Folder: {CERT_DIR}")
        return "\n".join(parts)

    def ui_create_cert(self):
        try:
            create_https_certificate()
            self.cert_status.setText(self.get_cert_status_text())
            QMessageBox.information(self, "Success", "Certificate created")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def ui_install_cert(self):
        try:
            if not os.path.exists(CERT_CER):
                raise RuntimeError("Create the certificate first")
            install_cert_admin()
            QMessageBox.information(self, "Success", "Confirm the admin prompt to install the certificate")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def ui_open_cert_folder(self):
        os.makedirs(CERT_DIR, exist_ok=True)
        try:
            os.startfile(CERT_DIR)
        except Exception:
            pass

    def save_settings_from_ui(self):
        self.client_id = (self.client_id_input.text() or "").strip()
        self.settings["client_id"] = self.client_id
        self.settings["quality"] = (self.quality_box.currentText() or "best").strip()
        self.settings["only_live"] = bool(self.only_live_toggle.isChecked())
        self.settings["embed_mpv"] = bool(self.embed_toggle.isChecked())
        self.settings["volume"] = int(self.volume_slider.value())
        save_json(SETTINGS_FILE, self.settings)
        self.status.setText("Settings saved")

    def token_valid(self, token):
        if not token:
            return False
        access = token.get("access_token")
        exp_at = token.get("expires_at", 0)
        return bool(access) and time.time() < (exp_at - 30)

    def ensure_token(self):
        if self.token_valid(self.token):
            return self.token["access_token"]

        if not self.token:
            raise RuntimeError("Not authorized")

        refresh = self.token.get("refresh_token")
        if not refresh:
            raise RuntimeError("Missing refresh token")

        fields = {
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": self.client_id,
        }

        resp = form_post("https://id.twitch.tv/oauth2/token", fields)

        access = resp.get("access_token")
        new_refresh = resp.get("refresh_token", refresh)
        expires_in = int(resp.get("expires_in", 0) or 0)

        if not access or expires_in <= 0:
            raise RuntimeError("Token refresh failed")

        self.token = {
            "access_token": access,
            "refresh_token": new_refresh,
            "expires_at": int(time.time()) + expires_in,
            "scope": resp.get("scope", SCOPES),
            "token_type": resp.get("token_type", "bearer"),
        }
        save_json(TOKEN_FILE, self.token)
        return self.token["access_token"]

    def twitch_headers(self):
        access = self.ensure_token()
        return {
            "Client-Id": self.client_id,
            "Authorization": f"Bearer {access}",
        }

    def ensure_user_id(self):
        headers = self.twitch_headers()
        me = http_json("https://api.twitch.tv/helix/users", headers=headers)
        data = me.get("data", [])
        if not data:
            raise RuntimeError("Could not fetch user")
        self.user_id = data[0].get("id")
        if not self.user_id:
            raise RuntimeError("Missing user id")

    def start_authorize(self):
        self.client_id = (self.client_id_input.text() or "").strip()
        if not self.client_id:
            QMessageBox.critical(self, "Error", "Set Client ID in Settings first")
            self.tabs.setCurrentIndex(self.settings_tab_index)
            return

        if not have_https_cert_files():
            QMessageBox.critical(self, "Error", "Create the HTTPS certificate in Settings first")
            self.tabs.setCurrentIndex(self.settings_tab_index)
            return

        self.settings["client_id"] = self.client_id
        save_json(SETTINGS_FILE, self.settings)

        self.stop_oauth_server()

        self.pkce_verifier, challenge = pkce_pair()
        self.oauth_state = secrets.token_urlsafe(16)

        OAuthHandler.bus = self.oauth_bus

        try:
            self.oauth_server = ThreadingHTTPServer((REDIRECT_HOST, REDIRECT_PORT), OAuthHandler)
            ctx = make_ssl_context()
            self.oauth_server.socket = ctx.wrap_socket(self.oauth_server.socket, server_side=True)
        except Exception as e:
            self.stop_oauth_server()
            QMessageBox.critical(self, "Error", f"Could not start HTTPS callback server: {e}")
            return

        self.oauth_thread = threading.Thread(target=self.oauth_server.serve_forever, daemon=True)
        self.oauth_thread.start()

        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": REDIRECT_URI,
            "scope": " ".join(SCOPES),
            "state": self.oauth_state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        url = "https://id.twitch.tv/oauth2/authorize?" + urllib.parse.urlencode(params)
        webbrowser.open(url)
        self.status.setText("Authorization opened in your browser")

    def stop_oauth_server(self):
        try:
            if self.oauth_server:
                self.oauth_server.shutdown()
        except Exception:
            pass
        try:
            if self.oauth_server:
                self.oauth_server.server_close()
        except Exception:
            pass
        self.oauth_server = None
        self.oauth_thread = None

    def on_oauth_code(self, code: str, state: str):
        if not self.oauth_state or state != self.oauth_state:
            self.stop_oauth_server()
            QMessageBox.critical(self, "Error", "Authorization state mismatch")
            return

        try:
            fields = {
                "client_id": self.client_id,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": self.pkce_verifier or "",
            }

            resp = form_post("https://id.twitch.tv/oauth2/token", fields)

            access = resp.get("access_token")
            refresh = resp.get("refresh_token")
            expires_in = int(resp.get("expires_in", 0) or 0)

            if not access or not refresh or expires_in <= 0:
                raise RuntimeError("Token exchange failed")

            self.token = {
                "access_token": access,
                "refresh_token": refresh,
                "expires_at": int(time.time()) + expires_in,
                "scope": resp.get("scope", SCOPES),
                "token_type": resp.get("token_type", "bearer"),
            }
            save_json(TOKEN_FILE, self.token)
            self.stop_oauth_server()

            self.ensure_user_id()
            self.refresh_follows(silent=True)

            self.status.setText("Authorized")
            self.tabs.setCurrentIndex(self.follows_tab_index)
        except Exception as e:
            self.stop_oauth_server()
            QMessageBox.critical(self, "Error", str(e))

    def clear_authorization(self):
        self.token = None
        self.user_id = None
        self.followed = []
        delete_file(TOKEN_FILE)
        self.follow_list.clear()
        self.status.setText("Not authorized")

    def refresh_follows(self, silent: bool):
        if not self.client_id:
            if not silent:
                QMessageBox.critical(self, "Error", "Set Client ID in Settings first")
            return
        if not self.token_valid(self.token):
            if not silent:
                QMessageBox.critical(self, "Error", "Authorize in browser first")
            return

        try:
            self.status.setText("Loading follows")
            QApplication.processEvents()

            if not self.user_id:
                self.ensure_user_id()

            headers = self.twitch_headers()

            follows = []
            cursor = None
            while True:
                params = {"user_id": self.user_id, "first": "100"}
                if cursor:
                    params["after"] = cursor
                url = "https://api.twitch.tv/helix/channels/followed?" + urllib.parse.urlencode(params)
                resp = http_json(url, headers=headers)
                data = resp.get("data", []) or []
                for x in data:
                    follows.append(
                        FollowedChannel(
                            broadcaster_id=str(x.get("broadcaster_id", "")),
                            login=str(x.get("broadcaster_login", "")),
                            display_name=str(x.get("broadcaster_name", "")),
                        )
                    )
                pag = resp.get("pagination", {}) or {}
                cursor = pag.get("cursor")
                if not cursor or len(data) == 0:
                    break

            live_map = self.fetch_live_map([f.broadcaster_id for f in follows], headers)
            for f in follows:
                s = live_map.get(f.broadcaster_id)
                if s:
                    f.live = True
                    f.title = s.get("title", "") or ""
                    f.game_name = s.get("game_name", "") or ""
                    f.viewer_count = int(s.get("viewer_count", 0) or 0)

            follows.sort(key=lambda x: (not x.live, (x.login or "").lower()))
            self.followed = follows
            self.render_follow_list()
            self.status.setText(f"Loaded {len(self.followed)} follows")
        except Exception as e:
            self.status.setText("")
            if not silent:
                QMessageBox.critical(self, "Error", str(e))

    def fetch_live_map(self, ids, headers):
        live = {}
        ids = [x for x in ids if x]
        for i in range(0, len(ids), 100):
            chunk = ids[i : i + 100]
            params = [("user_id", uid) for uid in chunk]
            url = "https://api.twitch.tv/helix/streams?" + urllib.parse.urlencode(params)
            resp = http_json(url, headers=headers)
            data = resp.get("data", []) or []
            for s in data:
                uid = str(s.get("user_id", ""))
                if uid:
                    live[uid] = s
        return live

    def render_follow_list(self):
        self.follow_list.clear()
        q = (self.filter_input.text() or "").strip().lower()
        only_live = bool(self.only_live_toggle.isChecked())

        for f in self.followed:
            if only_live and not f.live:
                continue

            name = f.login or ""
            if not name:
                continue

            if q and q not in name.lower():
                continue

            item = QListWidgetItem(name)
            item.setData(Qt.ItemDataRole.UserRole, name)

            if f.live:
                item.setForeground(Qt.GlobalColor.green)
            else:
                item.setForeground(Qt.GlobalColor.lightGray)

            self.follow_list.addItem(item)

    def on_follow_clicked(self, item: QListWidgetItem):
        ch = item.data(Qt.ItemDataRole.UserRole)
        if ch:
            self.tabs.setCurrentIndex(self.stream_tab_index)
            self.open_stream(ch)

    def render_recent(self):
        self.recent_list.clear()
        recents = self.settings.get("recent_channels", [])
        for ch in recents:
            item = QListWidgetItem(ch)
            item.setData(Qt.ItemDataRole.UserRole, ch)
            self.recent_list.addItem(item)

    def add_recent(self, channel: str):
        recents = self.settings.get("recent_channels", [])
        channel = normalize_channel(channel)
        if not channel:
            return
        recents = [c for c in recents if c.lower() != channel.lower()]
        recents.insert(0, channel)
        recents = recents[:60]
        self.settings["recent_channels"] = recents
        save_json(SETTINGS_FILE, self.settings)
        self.render_recent()

    def on_recent_clicked(self, item: QListWidgetItem):
        ch = item.data(Qt.ItemDataRole.UserRole)
        if ch:
            self.open_stream(ch)

    def open_from_input(self):
        ch = normalize_channel(self.channel_input.text())
        if not ch:
            QMessageBox.warning(self, "Error", "Enter a valid channel")
            return
        self.open_stream(ch)

    def stop_player(self):
        try:
            if self.mpv_process.state() != QProcess.ProcessState.NotRunning:
                self.mpv_process.terminate()
                self.mpv_process.waitForFinished(1500)
                if self.mpv_process.state() != QProcess.ProcessState.NotRunning:
                    self.mpv_process.kill()
                    self.mpv_process.waitForFinished(1500)
        except Exception:
            pass

    def open_stream(self, channel: str):
        channel = normalize_channel(channel)
        if not channel:
            return

        quality = (self.quality_box.currentText() or "best").strip() or "best"
        self.settings["quality"] = quality
        self.settings["embed_mpv"] = bool(self.embed_toggle.isChecked())
        self.settings["volume"] = int(self.volume_slider.value())
        save_json(SETTINGS_FILE, self.settings)

        self.add_recent(channel)

        self.chat_view.setUrl(QUrl(f"https://www.twitch.tv/popout/{channel}/chat?popout="))

        self.stop_player()

        try:
            stream_url = streamlink_stream_url(channel, quality)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            return

        args = [
            "--force-window=yes",
            "--idle=no",
            "--keep-open=no",
            "--profile=low-latency",
            "--cache=no",
            "--hwdec=d3d11va",
            "--vo=gpu",
            "--gpu-api=d3d11",
            "--gpu-context=d3d11",
            f"--input-ipc-server={MPV_IPC_PATH}",
            "--input-default-bindings=yes",
        ]

        if self.embed_toggle.isChecked():
            wid = int(self.video_container.winId())
            args.append(f"--wid={wid}")

        args.append(stream_url)

        self.mpv_process.setWorkingDirectory(self.mpv_workdir)
        self.mpv_process.start(self.mpv_path, args)

        if not self.mpv_process.waitForStarted(5000):
            QMessageBox.critical(self, "Error", f"mpv failed to start: {self.mpv_process.errorString()}")
            return

        self.apply_volume_to_mpv()
        self.status.setText(f"Playing {channel}")

    def apply_volume_to_mpv(self):
        v = int(self.volume_slider.value())
        try:
            mpv_ipc_send({"command": ["set_property", "volume", v]})
        except Exception:
            pass

    def on_volume_changed(self, value: int):
        self.volume_value.setText(str(int(value)))
        self.settings["volume"] = int(value)
        save_json(SETTINGS_FILE, self.settings)
        self.apply_volume_to_mpv()

    def closeEvent(self, event):
        self.stop_player()
        self.stop_oauth_server()
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    w = TwitchViewer()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
