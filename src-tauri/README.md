# EDR Desktop Application

A Tauri-based desktop wrapper that runs the EDR workbench locally without requiring manual CLI commands.

## Features

- **One-click launch**: Double-click to start, no terminal required
- **Auto backend management**: Spawns and manages the `ui_server` automatically
- **Deterministic storage**: All data stored in platform-standard locations
- **Clean shutdown**: Properly terminates backend on exit, no orphan processes
- **Fully offline**: No cloud calls, no telemetry uploads
- **Status indicator**: Shows backend status, port, and telemetry path in UI

## Prerequisites

### All Platforms

1. **Rust toolchain** (1.70+)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Tauri CLI**
   ```bash
   cargo install tauri-cli
   ```

### macOS

```bash
# Xcode Command Line Tools (required)
xcode-select --install
```

### Linux

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
    libssl-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev

# Fedora
sudo dnf install webkit2gtk4.1-devel openssl-devel curl wget file \
    gtk3-devel libappindicator-gtk3-devel librsvg2-devel

# Arch
sudo pacman -S webkit2gtk-4.1 base-devel curl wget file openssl \
    gtk3 libappindicator-gtk3 librsvg
```

### Windows (Optional)

```powershell
# Install Visual Studio Build Tools with C++ workload
# Or full Visual Studio with "Desktop development with C++"
# WebView2 is included in Windows 11, install separately for Windows 10
```

## Development

### Build the Backend First

```bash
# From repository root (NOT from src-tauri)
cd /path/to/git-glue
cargo build --release -p edr-server
```

Or from the server crate:
```bash
cd crates/server
cargo build --release
```

### Run in Development Mode

```bash
cd src-tauri
cargo tauri dev
```

This will:
1. Start the Tauri development server
2. Spawn the `ui_server` backend automatically
3. Open the workbench UI in a native window
4. Hot-reload on frontend changes

### Run Tests

```bash
cd src-tauri
cargo test
```

## Production Build

### Build Release

```bash
cd src-tauri
cargo tauri build
```

Output locations:
- **macOS**: `target/release/bundle/macos/EDR Desktop.app`
- **Linux**: `target/release/bundle/appimage/edr-desktop_*.AppImage`
- **Windows**: `target/release/bundle/msi/EDR Desktop_*.msi`

### macOS Code Signing (Optional)

For distribution outside the App Store:

```bash
# Sign the app
codesign --deep --force --verify --verbose \
    --sign "Developer ID Application: Your Name (TEAMID)" \
    "target/release/bundle/macos/EDR Desktop.app"

# Notarize (requires Apple Developer account)
xcrun notarytool submit "target/release/bundle/macos/EDR Desktop.app" \
    --apple-id "your@email.com" \
    --team-id "TEAMID" \
    --password "@keychain:AC_PASSWORD" \
    --wait

# Staple the ticket
xcrun stapler staple "target/release/bundle/macos/EDR Desktop.app"
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    EDR Desktop (Tauri)                  │
│  ┌───────────────────────────────────────────────────┐  │
│  │                  Tauri Window                     │  │
│  │  ┌─────────────────────────────────────────────┐  │  │
│  │  │          WebView (index.html)               │  │  │
│  │  │  - Dashboard UI                             │  │  │
│  │  │  - Status bar (Tauri-only)                  │  │  │
│  │  │  - Tauri IPC for commands                   │  │  │
│  │  └─────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────┘  │
│                          │                              │
│                   HTTP (127.0.0.1:8000)                 │
│                          │                              │
│  ┌───────────────────────────────────────────────────┐  │
│  │              ui_server (Child Process)            │  │
│  │  - /api/health, /api/alerts, etc.                │  │
│  │  - Serves static files from /ui/                 │  │
│  │  - Managed by BackendManager                     │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `EDR_TELEMETRY_ROOT` | Override telemetry storage location | Platform-specific app data |
| `EDR_SERVER_PORT` | Force specific port (set by Tauri) | 8000 |
| `RUST_LOG` | Logging level | `info,edr_desktop=debug` |

### Port Selection

The app uses deterministic port selection:

1. Try port **3000** (default)
2. If busy, try **3001-3010** sequentially
3. Fail with actionable error if all ports busy

### Storage Locations

| Platform | Telemetry | Logs |
|----------|-----------|------|
| macOS | `~/Library/Application Support/EDR Desktop/telemetry` | `~/Library/Application Support/EDR Desktop/logs` |
| Linux | `~/.local/share/EDR Desktop/telemetry` | `~/.local/share/EDR Desktop/logs` |
| Windows | `%LOCALAPPDATA%\EDR Desktop\telemetry` | `%LOCALAPPDATA%\EDR Desktop\logs` |

## Troubleshooting

### Backend fails to start

1. Check if `edr-server` binary exists:
   ```bash
   ls target/release/edr-server
   ```
   If missing, build it:
   ```bash
   cargo build --release -p edr-server
   ```

2. Check if ports 8000-8010 are all in use:
   ```bash
   lsof -i :8000-8010
   ```

3. Check logs:
   - macOS: `~/Library/Application Support/EDR Desktop/logs/`
   - Linux: `~/.local/share/EDR Desktop/logs/`

### "Backend started but health check failed"

The server may be slow to initialize. Wait a few seconds and try:
```bash
curl http://127.0.0.1:8000/api/health
```

### Orphan processes after crash

If the app crashes without cleanup:
```bash
# Find orphan ui_server processes
pgrep -f ui_server

# Kill them
pkill -f ui_server
```

## Tauri Commands (IPC)

Available from JavaScript via `window.__TAURI__.core.invoke()`:

| Command | Description | Returns |
|---------|-------------|---------|
| `get_status` | Get backend status | `{ running, port, telemetry_root, api_base_url, pid }` |
| `get_api_base_url` | Get API base URL | `string` |
| `open_telemetry_folder` | Open telemetry folder in file browser | `void` |
| `restart_backend` | Restart the backend server | `StatusInfo` |

## License

MIT
