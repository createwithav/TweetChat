# TweetChat
A real-time chat application demonstrating the comparative strengths of Go for backend systems programming and Rust (Leptos framework) for frontend development.

## Backend (Go) — Build & Run

This repository includes a Go backend in `Backend/` that provides:
- REST endpoints: `/api/register`, `/api/login`, `/servers/create` (requires Authorization header)
- WebSocket endpoint: `/ws/{serverName}` (query params `token` and `password`)

Prerequisites
- Go 1.20+ installed
- (Optional) `make` for the included Makefile

Quick start (Windows PowerShell)

1) Build the backend

```powershell
cd Backend
go build -o tweetchat-backend main.go
```

2) Run the backend

```powershell
# Run the built binary
.\\tweetchat-backend.exe
# Or run via `go run` during development
go run main.go
```

The backend listens on port `5000` by default (http://localhost:5000).

## Frontend (HTML/JavaScript) - Serving for Network Access

The frontend is located in `Frontend/simple-chat.html` and uses a simple HTML/JavaScript implementation that works across all devices.

### Quick Start for Network Access

To allow other devices on your local network to connect:

1. **Add Windows Firewall Rules** (run as Administrator):
```powershell
# Right-click on Backend/setup-firewall.bat and select "Run as administrator"
# This will open ports 5000 (backend) and 8000 (frontend)
```

2. **Start the Backend** (Terminal 1):
```powershell
cd Backend
.\tweetchat-backend.exe
# Or: go run main.go
```

3. **Start the Frontend Server** (Terminal 2):
```powershell
cd Frontend
python -m http.server 8000
# Or: .\serve-network.bat
```

4. **Access the Application**:
   - **On your computer**: http://localhost:8000
   - **From other devices on your WiFi**: http://YOUR_IP_ADDRESS:8000
   - Example: http://10.1.33.159:8000

5. **Find your local IP address**:
```powershell
ipconfig | Select-String "IPv4"
```
Look for your WiFi adapter's IPv4 address (e.g., `10.1.33.159`)

**Note**: 
- The backend is configured to listen on `0.0.0.0:5000` to accept connections from all network interfaces
- The frontend will automatically connect to the backend at the same IP address it was accessed from
- Both servers must be running for the application to work properly

## Testing the REST API (Postman / curl)

- Register a user (POST /api/register)
	- Body (JSON): `{ "username": "alice", "password": "secret" }`
- Login (POST /api/login)
	- Body (JSON): `{ "username": "alice", "password": "secret" }`
	- Response contains `{ "token": "...", "username": "alice" }`

Example using PowerShell + curl:

```powershell
# register
curl -X POST http://localhost:5000/api/register -H "Content-Type: application/json" -d '{"username":"alice","password":"secret"}'

# login
$resp = curl -s -X POST http://localhost:5000/api/login -H "Content-Type: application/json" -d '{"username":"alice","password":"secret"}' | ConvertFrom-Json
$token = $resp.token
```

In Postman, create a new request, set method to POST, URL to `http://localhost:5000/api/register`, Content-Type to `application/json`, and paste the JSON body. Repeat for `/api/login`.

## Connecting to the WebSocket

The WebSocket endpoint expects a valid user token (from login/register) and the server password as URL query parameters.

Example WebSocket URL (replace placeholders):

```
ws://localhost:5000/ws/<serverName>?token=<TOKEN>&password=<SERVER_PASSWORD>
```

Tools to test WebSocket connections
- wscat (npm) — quick, cross-platform CLI client
	- Install: `npm install -g wscat`
	- Connect: `wscat -c "ws://localhost:5000/ws/myroom?token=...&password=..."`
- websocat — powerful CLI WebSocket tool (Rust binary)
	- Install: see https://github.com/vi/websocat
	- Connect: `websocat "ws://localhost:5000/ws/myroom?token=...&password=..."`
- WebSocket King Client (Chrome extension) — GUI client for manual testing
- Postman (latest versions support WebSocket requests) — create a WS request, provide the URL and connect

Once connected, send JSON messages like:

```json
{ "content": "Hello everyone" }
```

Messages from the server are JSON objects with fields: `type`, `username`, `content`, `timestamp`.

## Notes & Suggestions
- Tokens are currently generated securely using crypto/rand and returned at registration/login. For production, consider JWT (stateless) or Redis-backed sessions to support revocation.
- The backend uses a pure-Go SQLite driver (no CGO required) and stores chat logs under `chat_logs/<serverName>/log.txt`.
- For production readiness:
	- Use TLS (HTTPS/WSS)
	- Use a database suited for concurrent writes if needed (Postgres)
	- Add rate limiting on auth endpoints
	- Use proper secrets management for signing keys and DB credentials

If you want, I can add quick Postman collections or example `curl` scripts for all endpoints and a small example showing how to create a server and join it over WebSocket.
