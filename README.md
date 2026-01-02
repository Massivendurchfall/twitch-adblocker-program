# Twitch Viewer

A desktop Twitch viewer for Windows built with Python and PyQt6.

It plays the stream using `streamlink` plus `mpv` and shows the chat on the right side inside the app.
It also supports OAuth so you can fetch your followed channels list.
The follow list shows only Twitch usernames.

## Features

- Watch any Twitch channel without logging in
- Chat on the right side
- Recent channels list on the left
- Followed channels list after OAuth authorization
- Volume slider inside the app
- One click open and stop
- Low latency stream playback via mpv

## Project structure

- `main.py` main application
- `build.py` PyInstaller onefile build script
- `oauth_cert/` generated HTTPS callback certificate files
- `web_profile/` web engine profile storage (created automatically)
- `mpv.exe` mpv player binary (put next to `main.py`)

## Requirements

- Windows 10 or Windows 11
- Python 3.11 or 3.12 recommended
- A Twitch Developer application
- mpv Windows build
- streamlink installed in your venv or bundled in your build

## Install

### 1 Clone

```bash
git clone <your-repo-url>
cd twitch_viewer
