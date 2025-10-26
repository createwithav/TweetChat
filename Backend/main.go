package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var (
	db       *sql.DB
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	hub        *Hub
	userTokens = make(map[string]string)
	tokenMutex = &sync.RWMutex{}
	logger     *zap.SugaredLogger
)

type ctxKey string

var ctxUserKey ctxKey = "username"

type Client struct {
	hub        *Hub
	conn       *websocket.Conn
	send       chan *Message
	serverName string
	username   string
}

type Message struct {
	Type      string `json:"type"`
	Content   string `json:"content"`
	Username  string `json:"username"`
	Timestamp string `json:"timestamp"` // Changed to string for proper serialization
	TimeStr   string `json:"timeStr"`   // HH:MM format timestamp
}

type Hub struct {
	servers    map[string]map[*Client]bool
	broadcast  chan *MessageWithServer
	register   chan *Client
	unregister chan *Client
	mutex      sync.RWMutex
	stop       chan struct{}
}

type MessageWithServer struct {
	Message    *Message
	ServerName string
}

// Credentials for user registration/login
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ServerCredentials for creating/joining a server
type ServerCredentials struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// AuthResponse is sent back on successful login/register
type AuthResponse struct {
	Token    string `json:"token"`
	Username string `json:"username"`
}

// --- Hub Logic ---

// NewHub creates a new Hub
func NewHub() *Hub {
	return &Hub{
		servers:    make(map[string]map[*Client]bool),
		broadcast:  make(chan *MessageWithServer, 256), // Add buffer to prevent blocking
		register:   make(chan *Client),
		unregister: make(chan *Client),
		stop:       make(chan struct{}),
	}
}

// Run starts the hub's event loop
func (h *Hub) Run() {
	if logger != nil {
		logger.Infof("Hub.Run() started")
	}
	if logger != nil {
		logger.Infof("Hub.Run() entered select loop")
	}
	for {
		select {
		case <-h.stop:
			if logger != nil {
				logger.Infof("Hub.Run() received stop signal")
			}
			return
		case client := <-h.register:
			if logger != nil {
				logger.Infof("Hub.Run() received register signal for client '%s'", client.username)
			}
			h.mutex.Lock()
			if _, ok := h.servers[client.serverName]; !ok {
				h.servers[client.serverName] = make(map[*Client]bool)
			}
			h.servers[client.serverName][client] = true
			h.mutex.Unlock()

			if logger != nil {
				logger.Infof("Client %s registered to server %s", client.username, client.serverName)
			}

			now := time.Now()
			joinMsg := &Message{
				Type:      "join",
				Username:  client.username,
				Timestamp: now.Format(time.RFC3339),
				TimeStr:   now.Format("15:04"),
				Content:   fmt.Sprintf("%s joined the chat", client.username),
			}
			h.broadcast <- &MessageWithServer{Message: joinMsg, ServerName: client.serverName}

		case client := <-h.unregister:
			h.mutex.Lock()
			if clients, ok := h.servers[client.serverName]; ok {
				if _, ok := clients[client]; ok {
					delete(clients, client)
					close(client.send)
					if len(clients) == 0 {
						delete(h.servers, client.serverName)
					}
				}
			}
			h.mutex.Unlock()

			if logger != nil {
				logger.Infof("Client %s unregistered from server %s", client.username, client.serverName)
			}

			now := time.Now()
			leaveMsg := &Message{
				Type:      "leave",
				Username:  client.username,
				Timestamp: now.Format(time.RFC3339),
				TimeStr:   now.Format("15:04"),
				Content:   fmt.Sprintf("%s left the chat", client.username),
			}
			h.broadcast <- &MessageWithServer{Message: leaveMsg, ServerName: client.serverName}

		case msgWithServer := <-h.broadcast:
			if logger != nil {
				logger.Infof("===== Hub received broadcast for server '%s': %+v", msgWithServer.ServerName, msgWithServer.Message)
			}

			// Store message in database for search functionality
			go func() {
				if err := dbStoreMessage(
					msgWithServer.ServerName,
					msgWithServer.Message.Username,
					msgWithServer.Message.Content,
					msgWithServer.Message.Type,
					msgWithServer.Message.TimeStr,
					msgWithServer.Message.Timestamp,
				); err != nil {
					if logger != nil {
						logger.Errorf("Failed to store message in database: %v", err)
					}
				} else {
					if logger != nil {
						logger.Infof("Successfully stored message in database for server '%s'", msgWithServer.ServerName)
					}
				}
			}()

			if msgWithServer.Message.Type == "chat" {
				go logMessage(msgWithServer.ServerName, msgWithServer.Message.Username, msgWithServer.Message.Content)
			}

			h.mutex.RLock()
			clients := h.servers[msgWithServer.ServerName]
			clientCount := len(clients)
			if logger != nil {
				logger.Infof("Server '%s' has %d clients", msgWithServer.ServerName, clientCount)
			}
			for client := range clients {
				if logger != nil {
					logger.Infof("Attempting to send message to client '%s' on server '%s'", client.username, client.serverName)
				}
				select {
				case client.send <- msgWithServer.Message:
					if logger != nil {
						logger.Infof("✓ Sent message to client '%s'", client.username)
					}
				default:
					if logger != nil {
						logger.Warnf("✗ Failed to send message to client '%s', closing connection", client.username)
					}
					close(client.send)
					delete(clients, client)
				}
			}
			h.mutex.RUnlock()
			if logger != nil {
				logger.Infof("===== Finished broadcasting message to server '%s'", msgWithServer.ServerName)
			}
		}
	}
}

func (h *Hub) Stop() {
	close(h.stop)
}

// --- Client Logic ---

// readPump pumps messages from the WebSocket connection to the hub.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadLimit(512)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		var msg struct {
			Content string `json:"content"`
		}

		if logger != nil {
			logger.Infof("Client '%s' waiting for message on server '%s'", c.username, c.serverName)
		}

		err := c.conn.ReadJSON(&msg)
		if err != nil {
			if logger != nil {
				logger.Infof("Client '%s' read error: %v", c.username, err)
			}
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				if logger != nil {
					logger.Errorf("websocket read error: %v", err)
				}
			}
			break
		}

		if logger != nil {
			logger.Infof("Client '%s' received message content: '%s' on server '%s'", c.username, msg.Content, c.serverName)
		}

		now := time.Now()
		fullMsg := &Message{
			Type:      "chat",
			Content:   msg.Content,
			Username:  c.username,
			Timestamp: now.Format(time.RFC3339),
			TimeStr:   now.Format("15:04"),
		}

		if logger != nil {
			logger.Infof("Client '%s' broadcasting message to server '%s': %+v", c.username, c.serverName, fullMsg)
		}

		if logger != nil {
			logger.Infof("Client '%s' sending message to hub.broadcast channel...", c.username)
		}
		c.hub.broadcast <- &MessageWithServer{Message: fullMsg, ServerName: c.serverName}
		if logger != nil {
			logger.Infof("Client '%s' successfully sent message to hub.broadcast channel", c.username)
		}
	}
}

// writePump pumps messages from the hub to the WebSocket connection.
func (c *Client) writePump() {
	ticker := time.NewTicker(45 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			err := c.conn.WriteJSON(message)
			if err != nil {
				if logger != nil {
					logger.Errorf("error writing json: %v", err)
				}
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// --- Chat Logging ---

// logMessage saves a chat message to the server's log file
func logMessage(serverName, username, content string) {
	safeServerName := filepath.Clean(serverName)
	if strings.Contains(safeServerName, "..") {
		if logger != nil {
			logger.Warnf("Invalid server name for logging: %s", serverName)
		}
		return
	}

	logDir := filepath.Join(".", "chat_logs", safeServerName)
	if err := os.MkdirAll(logDir, 0750); err != nil {
		if logger != nil {
			logger.Errorf("Error creating log directory: %v", err)
		}
		return
	}

	logFile := filepath.Join(logDir, "log.txt")
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		if logger != nil {
			logger.Errorf("Error opening log file: %v", err)
		}
		return
	}
	defer file.Close()

	timestamp := time.Now().Format(time.RFC3339)
	logEntry := fmt.Sprintf("[%s] %s: %s\n", timestamp, username, content)

	if _, err := file.WriteString(logEntry); err != nil {
		if logger != nil {
			logger.Errorf("Error writing to log file: %v", err)
		}
	}
}

// --- Database ---

// initDB initializes the SQLite database
func initDB() {
	var err error
	db, err = sql.Open("sqlite", "./chat.db")
	if err != nil {
		if logger != nil {
			logger.Fatalw("failed to open database", "error", err)
		}
	}

	usersTable := `
	CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL
	);
	`
	if _, err = db.Exec(usersTable); err != nil {
		if logger != nil {
			logger.Fatalw("failed to create users table", "error", err)
		}
	}

	serversTable := `
	CREATE TABLE IF NOT EXISTS servers (
		name TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL
	);
	`
	if _, err = db.Exec(serversTable); err != nil {
		if logger != nil {
			logger.Fatalw("failed to create servers table", "error", err)
		}
	}

	messagesTable := `
	CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		server_name TEXT NOT NULL,
		username TEXT NOT NULL,
		content TEXT NOT NULL,
		message_type TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		time_str TEXT NOT NULL
	);
	`
	if _, err = db.Exec(messagesTable); err != nil {
		if logger != nil {
			logger.Fatalw("failed to create messages table", "error", err)
		}
	}

	// Create index for better search performance
	indexSQL := `CREATE INDEX IF NOT EXISTS idx_messages_search ON messages(server_name, username, content, timestamp);`
	if _, err = db.Exec(indexSQL); err != nil {
		if logger != nil {
			logger.Fatalw("failed to create search index", "error", err)
		}
	}

	if logger != nil {
		logger.Infow("Database initialized successfully")
	}
}

// dbGetUser retrieves a user's hashed password
func dbGetUserHash(username string) (string, error) {
	var hash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&hash)
	return hash, err
}

// dbCreateUser adds a new user to the database
func dbCreateUser(username, hash string) error {
	_, err := db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, hash)
	return err
}

// dbGetServer retrieves a server's hashed password
func dbGetServerHash(name string) (string, error) {
	var hash string
	err := db.QueryRow("SELECT password_hash FROM servers WHERE name = ?", name).Scan(&hash)
	return hash, err
}

// dbCreateServer adds a new server to the database
func dbCreateServer(name, hash string) error {
	_, err := db.Exec("INSERT INTO servers (name, password_hash) VALUES (?, ?)", name, hash)
	return err
}

// dbStoreMessage stores a message in the database
func dbStoreMessage(serverName, username, content, messageType, timeStr, timestampStr string) error {
	// Parse the timestamp string to time.Time for database storage
	timestamp, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return err
	}
	_, err = db.Exec("INSERT INTO messages (server_name, username, content, message_type, timestamp, time_str) VALUES (?, ?, ?, ?, ?, ?)",
		serverName, username, content, messageType, timestamp, timeStr)
	return err
}

// SearchResult represents a search result
type SearchResult struct {
	ID          int       `json:"id"`
	ServerName  string    `json:"serverName"`
	Username    string    `json:"username"`
	Content     string    `json:"content"`
	MessageType string    `json:"messageType"`
	Timestamp   time.Time `json:"timestamp"`
	TimeStr     string    `json:"timeStr"`
}

// dbSearchMessages searches messages by username, content, or server name
func dbSearchMessages(query, searchType string, limit int) ([]SearchResult, error) {
	var rows *sql.Rows
	var err error

	baseQuery := "SELECT id, server_name, username, content, message_type, timestamp, time_str FROM messages WHERE "

	switch searchType {
	case "username":
		rows, err = db.Query(baseQuery+"username LIKE ? ORDER BY timestamp DESC LIMIT ?", "%"+query+"%", limit)
	case "content":
		rows, err = db.Query(baseQuery+"content LIKE ? ORDER BY timestamp DESC LIMIT ?", "%"+query+"%", limit)
	case "server":
		rows, err = db.Query(baseQuery+"server_name LIKE ? ORDER BY timestamp DESC LIMIT ?", "%"+query+"%", limit)
	case "all":
		rows, err = db.Query(baseQuery+"(username LIKE ? OR content LIKE ? OR server_name LIKE ?) ORDER BY timestamp DESC LIMIT ?",
			"%"+query+"%", "%"+query+"%", "%"+query+"%", limit)
	default:
		return nil, fmt.Errorf("invalid search type")
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []SearchResult
	for rows.Next() {
		var result SearchResult
		err := rows.Scan(&result.ID, &result.ServerName, &result.Username, &result.Content, &result.MessageType, &result.Timestamp, &result.TimeStr)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	return results, nil
}

// --- HTTP Handlers ---

// handleRegister handles new user registration
func handleRegister(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if creds.Username == "" || creds.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Username and password are required")
		return
	}

	if _, err := dbGetUserHash(creds.Username); err == nil {
		respondWithError(w, http.StatusConflict, "Username already exists")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	if err = dbCreateUser(creds.Username, string(hash)); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	token := generateToken()
	tokenMutex.Lock()
	userTokens[token] = creds.Username
	tokenMutex.Unlock()

	if logger != nil {
		logger.Infof("User registered: %s", creds.Username)
	}
	respondWithJSON(w, http.StatusCreated, AuthResponse{Token: token, Username: creds.Username})
}

// handleLogin handles user login
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	hash, err := dbGetUserHash(creds.Username)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(creds.Password)); err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	token := generateToken()
	tokenMutex.Lock()
	userTokens[token] = creds.Username
	tokenMutex.Unlock()

	if logger != nil {
		logger.Infof("User logged in: %s", creds.Username)
	}
	respondWithJSON(w, http.StatusOK, AuthResponse{Token: token, Username: creds.Username})
}

// handleSearch handles message search requests
func handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	searchType := r.URL.Query().Get("type")
	limitStr := r.URL.Query().Get("limit")

	if query == "" {
		respondWithError(w, http.StatusBadRequest, "Query parameter 'q' is required")
		return
	}

	if searchType == "" {
		searchType = "all"
	}

	limit := 50 // default limit
	if limitStr != "" {
		if parsedLimit, err := fmt.Sscanf(limitStr, "%d", &limit); err != nil || parsedLimit != 1 {
			respondWithError(w, http.StatusBadRequest, "Invalid limit parameter")
			return
		}
		if limit > 100 {
			limit = 100 // max limit
		}
		if limit < 1 {
			limit = 1 // min limit
		}
	}

	results, err := dbSearchMessages(query, searchType, limit)
	if err != nil {
		if logger != nil {
			logger.Errorf("Search error: %v", err)
		}
		respondWithError(w, http.StatusInternalServerError, "Search failed")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"results": results,
		"count":   len(results),
		"query":   query,
		"type":    searchType,
	})
}

// handleGetChatHistory handles requests for chat history
func handleGetChatHistory(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value(ctxUserKey).(string)
	if !ok {
		respondWithError(w, http.StatusInternalServerError, "Could not identify user")
		return
	}

	serverName := r.URL.Query().Get("server")
	if serverName == "" {
		respondWithError(w, http.StatusBadRequest, "Server name is required")
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 100 // default limit
	if limitStr != "" {
		if parsedLimit, err := fmt.Sscanf(limitStr, "%d", &limit); err != nil || parsedLimit != 1 {
			respondWithError(w, http.StatusBadRequest, "Invalid limit parameter")
			return
		}
		if limit > 500 {
			limit = 500 // max limit
		}
		if limit < 1 {
			limit = 1 // min limit
		}
	}

	query := fmt.Sprintf("SELECT id, server_name, username, content, message_type, timestamp, time_str FROM messages WHERE server_name = ? ORDER BY timestamp ASC LIMIT ?")
	rows, err := db.Query(query, serverName, limit)
	if err != nil {
		if logger != nil {
			logger.Errorf("Failed to query chat history: %v", err)
		}
		respondWithError(w, http.StatusInternalServerError, "Failed to retrieve chat history")
		return
	}
	defer rows.Close()

	var results []SearchResult
	for rows.Next() {
		var result SearchResult
		err := rows.Scan(&result.ID, &result.ServerName, &result.Username, &result.Content, &result.MessageType, &result.Timestamp, &result.TimeStr)
		if err != nil {
			if logger != nil {
				logger.Errorf("Failed to scan chat history row: %v", err)
			}
			continue
		}
		results = append(results, result)
	}

	if logger != nil {
		logger.Infof("User '%s' retrieved %d messages from server '%s'", username, len(results), serverName)
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"messages": results,
		"count":    len(results),
		"server":   serverName,
	})
}

// handleCreateServer handles new server creation
func handleCreateServer(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value(ctxUserKey).(string)
	if !ok {
		respondWithError(w, http.StatusInternalServerError, "Could not identify user")
		return
	}

	var creds ServerCredentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if creds.Name == "" || creds.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Server name and password are required")
		return
	}

	if _, err := dbGetServerHash(creds.Name); err == nil {
		respondWithError(w, http.StatusConflict, "Server name already exists")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	if err = dbCreateServer(creds.Name, string(hash)); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create server")
		return
	}

	if logger != nil {
		logger.Infof("Server '%s' created by user '%s'", creds.Name, username)
	}
	respondWithJSON(w, http.StatusCreated, map[string]string{"message": "Server created successfully"})
}

// handleWebSocket handles the WebSocket connection request
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverName := vars["serverName"]
	if serverName == "" {
		if logger != nil {
			logger.Warn("WebSocket connection attempt with empty server name")
		}
		respondWithError(w, http.StatusBadRequest, "Server name is required")
		return
	}

	token := r.URL.Query().Get("token")
	if logger != nil {
		logger.Infof("WebSocket connection attempt to server '%s' with token '%s'", serverName, token)
	}

	tokenMutex.RLock()
	username, ok := userTokens[token]
	tokenMutex.RUnlock()

	if !ok {
		if logger != nil {
			logger.Warnf("Invalid token attempt for server '%s'", serverName)
		}
		respondWithError(w, http.StatusUnauthorized, "Invalid or missing token")
		return
	}

	password := r.URL.Query().Get("password")
	serverHash, err := dbGetServerHash(serverName)
	if err != nil {
		if logger != nil {
			logger.Warnf("Server not found: '%s'", serverName)
		}
		respondWithError(w, http.StatusNotFound, "Server not found")
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(serverHash), []byte(password)); err != nil {
		if logger != nil {
			logger.Warnf("Invalid password for server '%s' by user '%s'", serverName, username)
		}
		respondWithError(w, http.StatusUnauthorized, "Invalid server password")
		return
	}

	if logger != nil {
		logger.Infof("Upgrading WebSocket connection for user '%s' to server '%s'", username, serverName)
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		if logger != nil {
			logger.Errorf("Failed to upgrade connection: %v", err)
		}
		return
	}

	if logger != nil {
		logger.Infof("WebSocket connection established for user '%s' to server '%s'", username, serverName)
	}

	client := &Client{
		hub:        hub,
		conn:       conn,
		send:       make(chan *Message, 256),
		serverName: serverName,
		username:   username,
	}
	client.hub.register <- client

	go client.writePump()
	go client.readPump()
}

// --- Middleware ---

// authMiddleware verifies the user's token
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondWithError(w, http.StatusUnauthorized, "Authorization header required")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			respondWithError(w, http.StatusUnauthorized, "Invalid Authorization header format")
			return
		}

		tokenMutex.RLock()
		username, ok := userTokens[tokenString]
		tokenMutex.RUnlock()

		if !ok {
			respondWithError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		ctx := context.WithValue(r.Context(), ctxUserKey, username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// simpleCORS allows all origins
func simpleCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// --- Helpers ---

// respondWithError sends a JSON error message
func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

// respondWithJSON sends a JSON response
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// generateToken creates a simple random token
func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// --- Main ---

func main() {
	// initialize structured logger
	l, err := zap.NewDevelopment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer l.Sync()
	logger = l.Sugar()

	initDB()
	defer db.Close()

	hub = NewHub()
	go hub.Run()

	r := mux.NewRouter()

	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/register", handleRegister).Methods("POST", "OPTIONS")
	api.HandleFunc("/login", handleLogin).Methods("POST", "OPTIONS")
	api.Handle("/servers/create", authMiddleware(http.HandlerFunc(handleCreateServer))).Methods("POST", "OPTIONS")
	api.Handle("/search", authMiddleware(http.HandlerFunc(handleSearch))).Methods("GET", "OPTIONS")
	api.Handle("/chat/history", authMiddleware(http.HandlerFunc(handleGetChatHistory))).Methods("GET", "OPTIONS")

	r.HandleFunc("/ws/{serverName}", handleWebSocket)

	handler := simpleCORS(r)

	port := "5000"
	srv := &http.Server{
		Addr:         "0.0.0.0:" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Infof("Server starting on port %s", port)
		logger.Infof("Server accessible at: http://localhost:%s", port)
		logger.Infof("For other devices on your network, use your local IP with port %s (e.g., http://10.1.33.159:%s)", port, port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("listen: %v", err)
		}
	}()

	// graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	logger.Infow("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Errorw("Server forced to shutdown", "error", err)
	}

	hub.Stop()
	db.Close()
	logger.Infow("Server stopped")
}
