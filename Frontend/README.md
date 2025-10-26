# TweetChat Frontend

A modern chat application frontend built with Leptos (Rust) and Tailwind CSS, designed to work with the Go backend.

## Features

- **User Authentication**: Login and registration
- **Real-time Chat**: WebSocket-based messaging
- **Server Management**: Create and join chat servers
- **Message Search**: Search through chat history
- **Responsive Design**: Works on desktop and mobile
- **Modern UI**: Clean, modern interface with Tailwind CSS

## Prerequisites

- Rust (latest stable version)
- wasm-pack
- A web server to serve the built files

## Setup

1. **Install wasm-pack** (if not already installed):
   ```bash
   curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
   ```

2. **Build the frontend**:
   ```bash
   chmod +x build.sh
   ./build.sh
   ```

   Or manually:
   ```bash
   wasm-pack build --target web --out-dir pkg --dev
   ```

3. **Serve the files**:
   ```bash
   # Using Python
   python -m http.server 8000
   
   # Using Node.js (if you have http-server installed)
   npx http-server
   
   # Using any other web server
   # Just serve the files from the Frontend directory
   ```

4. **Open in browser**:
   Navigate to `http://localhost:8000`

## Backend Requirements

Make sure your Go backend is running on `http://localhost:5000` with the following endpoints:

- `POST /api/register` - User registration
- `POST /api/login` - User login
- `POST /api/servers/create` - Create server (requires auth)
- `GET /api/search` - Search messages (requires auth)
- `WS /ws/{serverName}` - WebSocket connection

## Usage

1. **Register/Login**: Create an account or login with existing credentials
2. **Create Server**: Create a new chat server with a name and password
3. **Join Server**: Join an existing server using its name and password
4. **Chat**: Send and receive messages in real-time
5. **Search**: Use the search functionality to find messages by username, content, or server

## Development

To modify the frontend:

1. Edit `src/main.rs` for the main application logic
2. Edit `index.html` for the HTML structure and styling
3. Run `wasm-pack build --target web --out-dir pkg --dev` to rebuild
4. Refresh your browser to see changes

## Project Structure

```
Frontend/
├── Cargo.toml          # Rust dependencies
├── index.html          # HTML entry point
├── src/
│   └── main.rs         # Main Leptos application
├── build.sh            # Build script
└── README.md           # This file
```

## Troubleshooting

- **CORS Issues**: Make sure your backend has CORS enabled for `localhost:8000`
- **WebSocket Connection Failed**: Check that the backend is running and the server name/password are correct
- **Build Errors**: Ensure you have the latest version of Rust and wasm-pack
- **Module Not Found**: Make sure you're serving the files from a web server, not opening the HTML file directly

## API Integration

The frontend integrates with the following backend endpoints:

- **Authentication**: Uses Bearer token authentication
- **WebSocket**: Connects to `/ws/{serverName}` with token and password parameters
- **Search**: Supports searching by username, content, server name, or all
- **Real-time**: Messages are sent/received via WebSocket for real-time chat
