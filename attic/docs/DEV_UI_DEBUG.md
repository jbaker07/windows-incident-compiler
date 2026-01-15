# UI Debug Guide: JavaScript Syntax Errors

## Problem: "Unexpected end of input" errors in browser console

This error typically means one of:
1. **Truncated JavaScript file** - the file ends prematurely
2. **Missing closing braces/parentheses** - IIFE or function not properly closed
3. **Server serving wrong content** - HTML returned instead of JS

## Diagnosis Steps

### Step 1: Verify file is served correctly (not truncated, not HTML)

```powershell
# Check Content-Type and first few lines
curl -i http://127.0.0.1:3000/ui/app.js | Select-Object -First 10

# Check last lines (should end with })();)
curl -s http://127.0.0.1:3000/ui/app.js | Select-Object -Last 10

# Verify it's not HTML (should NOT start with <!DOCTYPE)
curl -s http://127.0.0.1:3000/ui/app.js | Select-Object -First 3
```

### Step 2: Check file on disk

```powershell
# Last 10 lines
Get-Content "ui\app.js" -Tail 10

# File size
(Get-Item "ui\app.js").Length

# Line count
(Get-Content "ui\app.js").Count
```

### Step 3: Check brace balance

```powershell
$content = Get-Content "ui\app.js" -Raw
$opens = ([regex]::Matches($content, '\{')).Count
$closes = ([regex]::Matches($content, '\}')).Count
"Opens: $opens, Closes: $closes, Diff: $($opens - $closes)"
```

**Diff should be 0** for a properly balanced file.

### Step 4: If truncated, compare with git

```powershell
# Check last known good version
git show HEAD:ui/app.js | Select-Object -Last 20

# Check if file was committed truncated
git log --oneline -5 -- ui/app.js
```

## Common Fixes

### Fix 1: Add missing IIFE closing

If the file starts with `(() => {` but doesn't end with `})();`:

```powershell
Add-Content "ui\app.js" "`n`n})();"
```

### Fix 2: Restart server after fixing

The server may cache files. Restart to serve the updated version:

```powershell
Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue | 
  ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
Start-Sleep 2
.\target\debug\edr-server.exe
```

### Fix 3: Hard refresh browser

After fixing the file and restarting the server:
- Chrome/Edge: `Ctrl+Shift+R` (Windows) or `Cmd+Shift+R` (Mac)
- Or open DevTools > Network tab > check "Disable cache" > reload

## Prevention

1. **Always validate JS before committing:**
   ```powershell
   # If Node is available
   node --check ui/app.js
   
   # Or check brace balance
   $content = Get-Content "ui\app.js" -Raw
   $diff = ([regex]::Matches($content, '\{')).Count - ([regex]::Matches($content, '\}')).Count
   if ($diff -ne 0) { throw "Brace imbalance: $diff" }
   ```

2. **Ensure IIFE structure:**
   - File starts with: `(() => {` or `(function() {`
   - File ends with: `})();`

## Related Files

- `ui/app.js` - Main UI JavaScript (IIFE wrapper)
- `ui/index.html` - HTML that loads app.js
- `crates/server/src/main.rs` - Static file serving

## History

- 2026-01-10: Fixed truncated app.js missing IIFE closing `})();`
