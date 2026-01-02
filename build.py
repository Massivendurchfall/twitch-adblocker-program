import os
import shutil
import subprocess
import sys
from pathlib import Path


APP_NAME = "TwitchViewer"
ENTRY_FILE = "main.py"

BASE_DIR = Path(__file__).resolve().parent
DIST_DIR = BASE_DIR / "dist"
BUILD_DIR = BASE_DIR / "build"
SPEC_FILE = BASE_DIR / f"{APP_NAME}.spec"


def run(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, shell=False)
    if p.returncode != 0:
        raise SystemExit(p.returncode)


def ensure_pyinstaller():
    try:
        import PyInstaller  # noqa: F401
        return
    except Exception:
        run([sys.executable, "-m", "pip", "install", "pyinstaller"])


def clean():
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR, ignore_errors=True)
    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR, ignore_errors=True)
    if SPEC_FILE.exists():
        try:
            SPEC_FILE.unlink()
        except Exception:
            pass


def find_in_venv_scripts(filename: str):
    scripts_dir = Path(sys.executable).resolve().parent
    p = scripts_dir / filename
    if p.exists():
        return p
    return None


def find_streamlink_exe():
    p = find_in_venv_scripts("streamlink.exe")
    if p:
        return p
    which = shutil.which("streamlink")
    if which and which.lower().endswith(".exe"):
        return Path(which)
    return None


def find_mpv_exe():
    p = BASE_DIR / "mpv.exe"
    if p.exists():
        return p
    which = shutil.which("mpv")
    if which and which.lower().endswith(".exe"):
        return Path(which)
    return None


def main():
    entry = BASE_DIR / ENTRY_FILE
    if not entry.exists():
        raise SystemExit(f"Entry file not found: {entry}")

    ensure_pyinstaller()
    clean()

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        str(entry),
        "--name",
        APP_NAME,
        "--noconfirm",
        "--clean",
        "--windowed",
        "--onefile",
        "--log-level",
        "WARN",
        "--collect-all",
        "PyQt6",
        "--collect-all",
        "PyQt6.QtWebEngineCore",
        "--collect-all",
        "PyQt6.QtWebEngineWidgets",
        "--collect-all",
        "PyQt6.QtWebChannel",
        "--collect-all",
        "cryptography",
        "--hidden-import",
        "PyQt6.sip",
        "--hidden-import",
        "PyQt6.QtCore",
        "--hidden-import",
        "PyQt6.QtGui",
        "--hidden-import",
        "PyQt6.QtWidgets",
        "--hidden-import",
        "PyQt6.QtNetwork",
        "--hidden-import",
        "PyQt6.QtWebEngineCore",
        "--hidden-import",
        "PyQt6.QtWebEngineWidgets",
        "--hidden-import",
        "PyQt6.QtWebChannel",
        "--hidden-import",
        "cryptography.hazmat",
        "--hidden-import",
        "cryptography.hazmat.backends",
        "--hidden-import",
        "cryptography.hazmat.bindings._rust",
        "--hidden-import",
        "cryptography.x509",
        "--hidden-import",
        "cryptography.hazmat.primitives",
        "--hidden-import",
        "cryptography.hazmat.primitives.serialization",
        "--hidden-import",
        "cryptography.hazmat.primitives.asymmetric",
        "--hidden-import",
        "cryptography.hazmat.primitives.asymmetric.rsa",
        "--hidden-import",
        "cryptography.hazmat.primitives.hashes",
    ]

    mpv_exe = find_mpv_exe()
    if mpv_exe:
        cmd += ["--add-binary", f"{mpv_exe}{os.pathsep}."]

    streamlink_exe = find_streamlink_exe()
    if streamlink_exe:
        cmd += ["--add-binary", f"{streamlink_exe}{os.pathsep}."]

    oauth_cert_dir = BASE_DIR / "oauth_cert"
    if oauth_cert_dir.exists():
        cmd += ["--add-data", f"{oauth_cert_dir}{os.pathsep}oauth_cert"]

    web_profile_dir = BASE_DIR / "web_profile"
    if web_profile_dir.exists():
        cmd += ["--add-data", f"{web_profile_dir}{os.pathsep}web_profile"]

    run(cmd, cwd=str(BASE_DIR))

    exe_path = DIST_DIR / f"{APP_NAME}.exe"
    if exe_path.exists():
        print(f"Build output: {exe_path}")
        if mpv_exe:
            print(f"Bundled mpv: {mpv_exe}")
        else:
            print("mpv.exe was not bundled (not found)")
        if streamlink_exe:
            print(f"Bundled streamlink: {streamlink_exe}")
        else:
            print("streamlink.exe was not bundled (not found)")
    else:
        print("Build finished but exe not found in dist")


if __name__ == "__main__":
    main()
