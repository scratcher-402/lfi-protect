package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type App struct {
	Config          *AdminConfig
	Router          *mux.Router
	Templates       *template.Template
	JWTSecret       []byte
	JWTSecretString string
	Trie            *Trie
	Logger          *Logger
	Proxy           *Proxy
}

func generateRandomSecret(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func NewApp(config *AdminConfig, logger *Logger, trie *Trie, proxy *Proxy) (*App, error) {
	// random jwt secret
	jwtSecret, err := generateRandomSecret(32)
	if err != nil {
		return nil, fmt.Errorf("JWT Secret generating error: %w", err)
	}

	templates := template.Must(template.ParseGlob("templates/*.html"))

	app := &App{
		Config:          config,
		Router:          mux.NewRouter(),
		Templates:       templates,
		JWTSecret:       []byte(jwtSecret),
		JWTSecretString: jwtSecret,
		Logger:          logger,
		Trie:            trie,
		Proxy:           proxy,
	}

	return app, nil
}

func (app *App) GenerateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)

	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "admin-panel",
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(app.JWTSecret)
}

func (app *App) ValidateJWT(tokenString string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signature algorithm: %v", token.Header["alg"])
		}
		return app.JWTSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("JWT parsing error: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("Invalid JWT")
	}

	return claims, nil
}

type contextKey string

const claimsKey contextKey = "claims"

func (app *App) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var tokenString string

		cookie, err := r.Cookie("auth_token")
		if err == nil {
			tokenString = cookie.Value
		} else {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
				tokenString = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if tokenString == "" {
			if strings.Contains(r.Header.Get("Accept"), "application/json") {
				app.JSONError(w, "Unauthorized", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}

		claims, err := app.ValidateJWT(tokenString)
		if err != nil {
			if strings.Contains(r.Header.Get("Accept"), "application/json") {
				app.JSONError(w, "Invalid token", http.StatusUnauthorized)
			} else {
				http.SetCookie(w, &http.Cookie{
					Name:     "auth_token",
					Value:    "",
					Path:     "/",
					Expires:  time.Now().Add(-time.Hour),
					HttpOnly: true,
				})
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}

		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (app *App) AdminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(claimsKey).(*Claims)
		if !ok {
			app.JSONError(w, "Permission denied", http.StatusForbidden)
			return
		}

		if claims.Username != app.Config.Username {
			app.JSONError(w, "You're not an admin (how is that even possible?!)", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func (app *App) JSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := APIResponse{
		Success: true,
		Data:    data,
	}

	json.NewEncoder(w).Encode(response)
}

func (app *App) JSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := APIResponse{
		Success: false,
		Error:   message,
	}

	json.NewEncoder(w).Encode(response)
}

func (app *App) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if cookie, err := r.Cookie("auth_token"); err == nil {
			if _, err := app.ValidateJWT(cookie.Value); err == nil {
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
		}

		data := map[string]interface{}{}
		app.Templates.ExecuteTemplate(w, "login.html", data)
		return
	}

	if r.Method == http.MethodPost {
		var req LoginRequest

		contentType := r.Header.Get("Content-Type")

		if strings.Contains(contentType, "application/json") {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				app.JSONError(w, "Invalid JSON", http.StatusBadRequest)
				return
			}
		} else {
			if err := r.ParseForm(); err != nil {
				app.JSONError(w, "Form parsing error", http.StatusBadRequest)
				return
			}
			req.Username = r.FormValue("username")
			req.Password = r.FormValue("password")
		}

		if req.Username != app.Config.Username {
			app.JSONError(w, "Invalid login or password", http.StatusUnauthorized)
			return
		}

		storedHash := app.Config.Password
		if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(req.Password)); err != nil {
			app.JSONError(w, "Invalid login or password", http.StatusUnauthorized)
			return
		}

		token, err := app.GenerateJWT(req.Username)
		if err != nil {
			app.JSONError(w, "Token generating error", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    token,
			Path:     "/",
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
			Secure:   false,
			SameSite: http.SameSiteStrictMode,
		})

		app.Logger.Event(LOG_INFO, "admin", fmt.Sprintf("User %s logged in", req.Username))
		if strings.Contains(contentType, "application/json") {
			app.JSONResponse(w, map[string]string{
				"token":   token,
				"message": "Login successful",
			}, http.StatusOK)
		} else {
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	}
}

type LogEntry struct {
	Level    int    `json:"Level"`
	Message  string `json:"Message"`
	UnixTime int64  `json:"UnixTime"`
	Category string `json:"Category"`
}

type LogsResponse struct {
	Logs      []LogEntry `json:"logs"`
	Total     int        `json:"total"`
	Filtered  int        `json:"filtered"`
	Returned  int        `json:"returned"`
	Timestamp int64      `json:"timestamp"`
}

func (app *App) apiLogsHandler(w http.ResponseWriter, r *http.Request) {
	priorityParam := r.URL.Query().Get("priority")
	limitParam := r.URL.Query().Get("limit")

	priority := 0
	limit := 100

	if priorityParam != "" {
		if p, err := strconv.Atoi(priorityParam); err == nil && p >= 0 && p <= 4 {
			priority = p
		}
	}

	if limitParam != "" {
		if l, err := strconv.Atoi(limitParam); err == nil && l > 0 {
			if l > 1000 {
				l = 1000
			}
			limit = l
		}
	}

	allLogs, err := app.readLogsFromFile()
	if err != nil {
		app.JSONError(w, "Failed to read logs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	filteredLogs := make([]LogEntry, 0)
	for _, log := range allLogs {
		if log.Level >= priority {
			filteredLogs = append(filteredLogs, log)
		}
	}

	start := 0
	if len(filteredLogs) > limit {
		start = len(filteredLogs) - limit
	}

	resultLogs := filteredLogs[start:]

	response := LogsResponse{
		Logs:      resultLogs,
		Total:     len(allLogs),
		Filtered:  len(filteredLogs),
		Returned:  len(resultLogs),
		Timestamp: time.Now().Unix(),
	}

	app.JSONResponse(w, response, http.StatusOK)
}

func (app *App) readLogsFromFile() ([]LogEntry, error) {
	file, err := os.Open(app.Logger.infoJsonlPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	logs := make([]LogEntry, 0)

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		var log LogEntry
		line := scanner.Bytes()

		if err := json.Unmarshal(line, &log); err != nil {
			continue
		}

		logs = append(logs, log)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return logs, nil
}

func (app *App) logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	})

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		app.JSONResponse(w, map[string]string{"message": "Login successful"}, http.StatusOK)
	} else {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func (app *App) indexHandler(w http.ResponseWriter, r *http.Request) {
	claims, _ := r.Context().Value(claimsKey).(*Claims)

	filesInTrie := len(app.Trie.Files)
	requestsHandled := app.Proxy.RequestsHandled
	requestsBlocked := app.Proxy.RequestsBlocked

	data := map[string]interface{}{
		"Username":        claims.Username,
		"FilesInTrie":     filesInTrie,
		"RequestsHandled": requestsHandled,
		"RequestsBlocked": requestsBlocked,
	}

	app.Templates.ExecuteTemplate(w, "index.html", data)
}

func (app *App) logsHandler(w http.ResponseWriter, r *http.Request) {
	claims, _ := r.Context().Value(claimsKey).(*Claims)

	data := map[string]interface{}{
		"Username": claims.Username,
	}

	app.Templates.ExecuteTemplate(w, "logs.html", data)
}

func (app *App) staticHandler() http.Handler {
	return http.StripPrefix("/static/", http.FileServer(http.Dir("./static")))
}

func (app *App) setupRoutes() {
	app.Router.PathPrefix("/static/").Handler(app.staticHandler())

	app.Router.HandleFunc("/login", app.loginHandler).Methods("GET", "POST")
	app.Router.HandleFunc("/logout", app.logoutHandler).Methods("GET", "POST")

	protected := app.Router.PathPrefix("/").Subrouter()
	protected.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(app.AuthMiddleware(next.ServeHTTP))
	})

	protected.HandleFunc("/", app.indexHandler).Methods("GET")
	protected.HandleFunc("/logs", app.logsHandler).Methods("GET")

	protected.HandleFunc("/api/logs", app.apiLogsHandler).Methods("GET")

}

func (app *App) Run() {
	if !app.Config.Enabled {
		return
	}
	app.setupRoutes()

	addr := app.Config.Listen
	app.Logger.Event(LOG_INFO, "admin", fmt.Sprintf("Admin panel listening at %s", addr))
	fmt.Println("Admin panel listening at", addr)
	err := http.ListenAndServe(addr, app.Router)
	if err != nil {
		fmt.Println("app error:", err)
	}
}
