# TweetChat Frontend - Troubleshooting Guide

## Quick Start (No Rust/WebAssembly needed)

If you're having issues with the Rust/Leptos setup, you can use the simple HTML version:

1. **Open `simple-chat.html`** directly in your browser
2. **Or serve it with a web server**:
   ```bash
   # Using Python
   python -m http.server 8000
   
   # Using Node.js
   npx http-server -p 8080
   
   # Or just double-click serve.bat
   ```

## Common Issues and Solutions

### 1. "wasm-pack not found" Error

**Problem**: The build process fails because wasm-pack is not installed.

**Solutions**:
- **Option A**: Use the simple HTML version (`simple-chat.html`)
- **Option B**: Install Visual Studio Build Tools:
  1. Download from: https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022
  2. Install with "C++ build tools" workload
  3. Run: `cargo install wasm-pack`
- **Option C**: Download pre-built wasm-pack binary from GitHub releases

### 2. "link.exe not found" Error

**Problem**: Visual Studio Build Tools are not installed.

**Solution**: Install Visual Studio Build Tools (see above) or use the simple HTML version.

### 3. "Backend connection failed"

**Problem**: The Go backend is not running or not accessible.

**Solutions**:
1. Make sure your Go backend is running on `localhost:5000`
2. Check if the backend is accessible: `curl http://localhost:5000/api/login`
3. Verify CORS settings in your backend

### 4. "WebSocket connection failed"

**Problem**: WebSocket connection to the backend fails.

**Solutions**:
1. Check if the backend is running
2. Verify the server name and password are correct
3. Check browser console for detailed error messages
4. Ensure the backend WebSocket endpoint is working

### 5. "CORS errors" in browser console

**Problem**: Cross-Origin Resource Sharing issues.

**Solution**: Your Go backend already has CORS enabled, but if you're still getting errors:
1. Make sure you're serving the frontend from a web server (not file://)
2. Check that the backend CORS settings allow your frontend origin

### 6. "Module not found" errors

**Problem**: JavaScript modules can't be loaded.

**Solutions**:
1. Make sure you're serving files from a web server
2. Don't open HTML files directly in browser (file:// protocol)
3. Use `serve.bat` or a proper web server

## Testing Your Setup

### 1. Test Backend
```bash
# Test if backend is running
curl http://localhost:5000/api/login

# Should return: {"error":"Invalid request payload"}
```

### 2. Test Frontend
1. Open browser developer tools (F12)
2. Check console for errors
3. Try registering a new user
4. Try creating a server
5. Try joining a server and sending messages

### 3. Test WebSocket
1. Open browser developer tools
2. Go to Network tab
3. Try joining a server
4. Look for WebSocket connection in the Network tab

## Alternative Solutions

### If Rust/WebAssembly doesn't work:

1. **Use the simple HTML version** (`simple-chat.html`)
   - No compilation needed
   - Works in any modern browser
   - Same functionality as the Rust version

2. **Use a different frontend framework**:
   - React + TypeScript
   - Vue.js
   - Angular
   - Plain JavaScript

### If you want to stick with Rust:

1. **Use WSL (Windows Subsystem for Linux)**:
   ```bash
   # In WSL
   curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
   wasm-pack build --target web --out-dir pkg --dev
   ```

2. **Use Docker**:
   ```dockerfile
   FROM rust:latest
   RUN curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
   # ... rest of your Dockerfile
   ```

## File Structure

```
Frontend/
├── simple-chat.html      # ← Use this if Rust doesn't work
├── serve.bat             # ← Simple server script
├── Cargo.toml            # Rust dependencies
├── src/main.rs           # Leptos application
├── build.bat             # Rust build script
├── install-wasm-pack.bat # wasm-pack installer
└── TROUBLESHOOTING.md    # This file
```

## Getting Help

1. Check browser console for errors
2. Check backend logs
3. Verify all URLs are correct
4. Make sure all services are running
5. Try the simple HTML version first

## Recommended Workflow

1. **Start with simple-chat.html** - it's easier to debug
2. **Get the backend working** - test with curl or Postman
3. **Test the simple frontend** - register, login, create server, chat
4. **If everything works**, then try the Rust version
5. **If Rust doesn't work**, stick with the simple version

The simple HTML version has the same functionality as the Rust version, just without the compilation step!

