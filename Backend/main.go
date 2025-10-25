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
	Type      string    `json:"type"`
	Content   string    `json:"content"`
	Username  string    `json:"username"`
	Timestamp time.Time `json:"timestamp"`
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
		broadcast:  make(chan *MessageWithServer),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		stop:       make(chan struct{}),
	}
}

// Run starts the hub's event loop
func (h *Hub) Run() {
	for {
		select {
		case <-h.stop:
			return
		case client := <-h.register:
			h.mutex.Lock()
			if _, ok := h.servers[client.serverName]; !ok {
				h.servers[client.serverName] = make(map[*Client]bool)
			}
			h.servers[client.serverName][client] = true
			h.mutex.Unlock()

			if logger != nil {
				logger.Infof("Client %s registered to server %s", client.username, client.serverName)
			}

			joinMsg := &Message{
				Type:      "join",
				Username:  client.username,
				Timestamp: time.Now(),
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

			leaveMsg := &Message{
				Type:      "leave",
				Username:  client.username,
				Timestamp: time.Now(),
				Content:   fmt.Sprintf("%s left the chat", client.username),
			}
			h.broadcast <- &MessageWithServer{Message: leaveMsg, ServerName: client.serverName}

		case msgWithServer := <-h.broadcast:
			if msgWithServer.Message.Type == "chat" {
				go logMessage(msgWithServer.ServerName, msgWithServer.Message.Username, msgWithServer.Message.Content)
			}

			h.mutex.RLock()
			clients := h.servers[msgWithServer.ServerName]
			for client := range clients {
				select {
				case client.send <- msgWithServer.Message:
				default:
					close(client.send)
					delete(clients, client)
				}
			}
			h.mutex.RUnlock()
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
		err := c.conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				if logger != nil {
					logger.Errorf("websocket read error: %v", err)
				}
			}
			break
		}

		fullMsg := &Message{
			Type:      "chat",
			Content:   msg.Content,
			Username:  c.username,
			Timestamp: time.Now(),
		}

		c.hub.broadcast <- &MessageWithServer{Message: fullMsg, ServerName: c.serverName}
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
		respondWithError(w, http.StatusBadRequest, "Server name is required")
		return
	}

	token := r.URL.Query().Get("token")
	tokenMutex.RLock()
	username, ok := userTokens[token]
	tokenMutex.RUnlock()

	if !ok {
		respondWithError(w, http.StatusUnauthorized, "Invalid or missing token")
		return
	}

	password := r.URL.Query().Get("password")
	serverHash, err := dbGetServerHash(serverName)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Server not found")
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(serverHash), []byte(password)); err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid server password")
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		if logger != nil {
			logger.Errorf("Failed to upgrade connection: %v", err)
		}
		return
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

	r.HandleFunc("/ws/{serverName}", handleWebSocket)

	handler := simpleCORS(r)

	port := "5000"
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Infof("Server starting on port %s", port)
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
