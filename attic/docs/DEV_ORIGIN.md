# Development Origin Architecture

This document explains how to correctly run the UI during development and why origin matters.

## The Problem

The Incident Compiler UI uses relative fetch paths for all API calls:
```javascript
fetch('/api/signals')     // Relative to current origin
fetch('/api/health')      // Same origin policy applies
```

This design is intentional: it allows the UI to work seamlessly when served by edr-server in production. However, during development, **the UI must be loaded from the same origin as the API**.

### Common Failure Mode

If the UI is loaded from a different origin (e.g., `file://`, or a dev server on port 1430), the relative API paths resolve to the wrong host:

| UI loaded from | `/api/health` resolves to | Result |
|----------------|--------------------------|--------|
| `http://127.0.0.1:3000/ui/index.html` | `http://127.0.0.1:3000/api/health` | ✅ Works |
| `file:///C:/path/ui/index.html` | `file:///api/health` | ❌ Fails |
| `http://127.0.0.1:1430/index.html` | `http://127.0.0.1:1430/api/health` | ❌ Returns HTML fallback |

## Solution: Load UI from edr-server (port 3000)

**Always load the UI from edr-server at port 3000.**

### Step 1: Start the Backend

```powershell
# From project root
cd C:\Users\Jermaine B\src\windows-incident-compiler
cargo run -p edr-server --bin edr-server
```

Wait for:
```
🚀 Attack Documentation Workbench running at http://0.0.0.0:3000
```

### Step 2: Open UI in Browser

Navigate to:
```
http://127.0.0.1:3000/ui/index.html
```

**Do NOT** open `ui/index.html` directly as a file. Use the URL.

### Step 3: Validate (DevTools)

Open browser DevTools (F12) → Network tab:
1. Filter by "XHR" or "Fetch"
2. Reload the page
3. Verify `/api/health` returns JSON with `200 OK`

### curl Validation

```powershell
# Health check
curl http://127.0.0.1:3000/api/health
# Expected: {"status":"ok"}

# Verify static files served
curl -I http://127.0.0.1:3000/ui/app.js
# Expected: Content-Type: text/javascript
```

## Boot Check Banner

The UI includes a backend boot check that shows a warning banner if:

1. **Backend offline**: `/api/health` times out or fails to connect
2. **Wrong origin**: `/api/health` returns HTML instead of JSON
3. **Server error**: `/api/health` returns non-200 status

The banner provides specific guidance based on the failure mode.

## Tauri Desktop Development

When developing the Tauri desktop app:

1. Start edr-server first (`cargo run -p edr-server --bin edr-server`)
2. Configure Tauri to load from `http://127.0.0.1:3000/ui/index.html` (not local files)
3. The Rust commands in Tauri still use `127.0.0.1:3000` for API calls

### Tauri Dev Server Pitfall

The Tauri v2 dev server runs on port 1430 by default. If you configure `frontendDist` to serve local UI files:
- UI loads from `:1430`
- Relative `/api/*` calls go to `:1430`
- `:1430` returns HTML fallback (no API routes)
- JSON parsing fails → UI broken

**Solution**: In dev mode, point Tauri's dev URL to the edr-server:
```json
{
  "build": {
    "devUrl": "http://127.0.0.1:3000/ui/index.html"
  }
}
```

## File Structure

```
crates/server/src/main.rs    # edr-server (port 3000)
  └── /ui/*                  # Serves ui/ directory via ServeDir
  └── /api/*                 # API endpoints

ui/
  └── index.html             # Main dashboard
  └── app.js                 # Frontend logic (relative fetches)
  └── loading.html           # Loading screen
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Backend offline" banner | edr-server not running | `cargo run -p edr-server --bin edr-server` |
| "API returning HTML" banner | UI loaded from wrong origin | Open `http://127.0.0.1:3000/ui/index.html` |
| "SyntaxError: Unexpected token '<'" | Fetch got HTML instead of JSON | Wrong origin, see above |
| CORS errors | Loading from `file://` | Use HTTP URL from edr-server |
| Buttons not working | JavaScript errors from API failures | Fix origin first, check console |

## See Also

- [DESKTOP_ARCHITECTURE.md](DESKTOP_ARCHITECTURE.md) - Tauri app architecture
- [ui_workflow.md](ui_workflow.md) - UI workflow documentation
