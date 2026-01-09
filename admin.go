package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
	"context"
	"strconv"
	"os"
	"bufio"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt/v5"
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
	Config     *AdminConfig
	Router     *mux.Router
	Templates  *template.Template
	JWTSecret  []byte
	JWTSecretString string
	Trie *Trie
	Logger *Logger
	Proxy *Proxy
}

// Генерация случайного секретного ключа
func generateRandomSecret(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// Инициализация
func NewApp(config *AdminConfig, logger *Logger, trie *Trie, proxy *Proxy) (*App, error) {
	// Генерируем случайный JWT секрет
	jwtSecret, err := generateRandomSecret(32)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации секретного ключа: %w", err)
	}

	// Загрузка шаблонов
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


// JWT Функции
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
		// Проверяем метод подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("неожиданный метод подписи: %v", token.Header["alg"])
		}
		return app.JWTSecret, nil
	})
	
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга токена: %w", err)
	}
	
	if !token.Valid {
		return nil, fmt.Errorf("невалидный токен")
	}
	
	return claims, nil
}

// Middleware
type contextKey string

const claimsKey contextKey = "claims"

func (app *App) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Получаем токен из куки или заголовка
		var tokenString string
		
		// Сначала проверяем куку
		cookie, err := r.Cookie("auth_token")
		if err == nil {
			tokenString = cookie.Value
		} else {
			// Проверяем заголовок Authorization
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
				tokenString = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}
		
		if tokenString == "" {
			if strings.Contains(r.Header.Get("Accept"), "application/json") {
				app.JSONError(w, "Требуется аутентификация", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}
		
		// Валидируем токен
		claims, err := app.ValidateJWT(tokenString)
		if err != nil {
			if strings.Contains(r.Header.Get("Accept"), "application/json") {
				app.JSONError(w, "Невалидный токен", http.StatusUnauthorized)
			} else {
				// Удаляем невалидную куку
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
		
		// Добавляем claims в контекст
		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (app *App) AdminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(claimsKey).(*Claims)
		if !ok {
			app.JSONError(w, "Доступ запрещен", http.StatusForbidden)
			return
		}
		
		if claims.Username != app.Config.Username {
			app.JSONError(w, "Требуются права администратора", http.StatusForbidden)
			return
		}
		
		next.ServeHTTP(w, r)
	}
}

// Вспомогательные функции
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

// Обработчики
func (app *App) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Проверяем, есть ли уже валидный токен
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
		
		// Определяем Content-Type
		contentType := r.Header.Get("Content-Type")
		
		if strings.Contains(contentType, "application/json") {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				app.JSONError(w, "Неверный JSON", http.StatusBadRequest)
				return
			}
		} else {
			// Форма
			if err := r.ParseForm(); err != nil {
				app.JSONError(w, "Ошибка парсинга формы", http.StatusBadRequest)
				return
			}
			req.Username = r.FormValue("username")
			req.Password = r.FormValue("password")
		}
		
		// Проверяем учетные данные
		if req.Username != app.Config.Username {
			app.JSONError(w, "Неверное имя пользователя или пароль", http.StatusUnauthorized)
			return
		}
		
		// Проверяем пароль (bcrypt)
		storedHash := app.Config.Password
		if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(req.Password)); err != nil {
			app.JSONError(w, "Неверное имя пользователя или пароль", http.StatusUnauthorized)
			return
		}
		
		// Генерируем JWT токен
		token, err := app.GenerateJWT(req.Username)
		if err != nil {
			app.JSONError(w, "Ошибка генерации токена", http.StatusInternalServerError)
			return
		}
		
		// Устанавливаем куку
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
				"message": "Успешный вход",
			}, http.StatusOK)
		} else {
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	}
}

// Структура лога (уже должна быть)
type LogEntry struct {
	Level    int    `json:"Level"`
	Message  string `json:"Message"`
	UnixTime int64  `json:"UnixTime"`
	Category string `json:"Category"`
}

// Структура ответа API логов
type LogsResponse struct {
	Logs      []LogEntry `json:"logs"`
	Total     int        `json:"total"`      // Всего логов в файле
	Filtered  int        `json:"filtered"`   // Сколько подошло под фильтр
	Returned  int        `json:"returned"`   // Сколько вернули (≤ limit)
	Timestamp int64      `json:"timestamp"`  // Время генерации ответа
}

// Обработчик для /api/logs
func (app *App) apiLogsHandler(w http.ResponseWriter, r *http.Request) {
	// Парсим параметры
	priorityParam := r.URL.Query().Get("priority")
	limitParam := r.URL.Query().Get("limit")
	
	// Значения по умолчанию
	priority := 0  // По умолчанию все логи (Level ≥ 0)
	limit := 100   // По умолчанию 100 последних сообщений
	
	// Парсим приоритет
	if priorityParam != "" {
		if p, err := strconv.Atoi(priorityParam); err == nil && p >= 0 && p <= 4 {
			priority = p
		}
	}
	
	// Парсим лимит
	if limitParam != "" {
		if l, err := strconv.Atoi(limitParam); err == nil && l > 0 {
			if l > 1000 {
				l = 1000  // Максимальный лимит
			}
			limit = l
		}
	}
	
	// Читаем логи из файла
	allLogs, err := app.readLogsFromFile()
	if err != nil {
		app.JSONError(w, "Failed to read logs: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Фильтруем логи по приоритету (Level ≥ priority)
	filteredLogs := make([]LogEntry, 0)
	for _, log := range allLogs {
		if log.Level >= priority {
			filteredLogs = append(filteredLogs, log)
		}
	}
	
	// Берём последние limit сообщений (или все, если меньше limit)
	start := 0
	if len(filteredLogs) > limit {
		start = len(filteredLogs) - limit
	}
	
	resultLogs := filteredLogs[start:]
	
	// Формируем ответ
	response := LogsResponse{
		Logs:      resultLogs,
		Total:     len(allLogs),
		Filtered:  len(filteredLogs),
		Returned:  len(resultLogs),
		Timestamp: time.Now().Unix(),
	}
	
	app.JSONResponse(w, response, http.StatusOK)
}

// Функция чтения логов из файла (возвращает в хронологическом порядке, новые - в конце)
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
	
	// Файл уже должен быть в хронологическом порядке (старые - в начале, новые - в конце)
	// Если это не так, раскомментируйте сортировку ниже:
	
	/*
	// Сортируем по времени (старые - в начале, новые - в конце)
	sort.Slice(logs, func(i, j int) bool {
		return logs[i].UnixTime < logs[j].UnixTime
	})
	*/
	
	return logs, nil
}

// Альтернативная версия с более эффективной обработкой (читает файл с конца)
func (app *App) readLastLogs(priority, limit int) ([]LogEntry, int, int, error) {
	file, err := os.Open(app.Logger.infoJsonlPath)
	if err != nil {
		return nil, 0, 0, err
	}
	defer file.Close()
	
	// Получаем размер файла для чтения с конца
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, 0, 0, err
	}
	fileSize := fileInfo.Size()
	
	// Собираем логи с конца файла
	result := make([]LogEntry, 0)
	totalLines := 0
	matchedLines := 0
	
	const bufferSize = 64 * 1024 // 64KB
	buffer := make([]byte, bufferSize)
	remaining := fileSize
	
	// Читаем с конца файла
	for remaining > 0 && len(result) < limit {
		// Определяем размер следующего блока для чтения
		readSize := bufferSize
		if remaining < int64(readSize) {
			readSize = int(remaining)
		}
		
		// Смещаемся и читаем блок
		start := remaining - int64(readSize)
		_, err := file.Seek(start, 0)
		if err != nil {
			return nil, 0, 0, err
		}
		
		n, err := file.Read(buffer[:readSize])
		if err != nil {
			return nil, 0, 0, err
		}
		
		// Обрабатываем блок с конца
		for i := n - 1; i >= 0; i-- {
			if buffer[i] == '\n' {
				// Нашли конец строки, обрабатываем предыдущую строку
				if i+1 < n {
					line := buffer[i+1:n]
					if len(line) > 0 {
						totalLines++
						var log LogEntry
						if json.Unmarshal(line, &log) == nil {
							if log.Level >= priority {
								matchedLines++
								if len(result) < limit {
									// Добавляем в начало, так как читаем с конца
									result = append([]LogEntry{log}, result...)
								}
							}
						}
					}
				}
				n = i
			}
		}
		
		// Обрабатываем первую строку в блоке (может быть обрезанной)
		if n > 0 {
			line := buffer[:n]
			if len(line) > 0 {
				totalLines++
				var log LogEntry
				if json.Unmarshal(line, &log) == nil {
					if log.Level >= priority {
						matchedLines++
						if len(result) < limit {
							result = append([]LogEntry{log}, result...)
						}
					}
				}
			}
		}
		
		remaining -= int64(readSize)
	}
	
	// Если файл маленький и мы всё прочитали, получаем общее количество
	if remaining <= 0 {
		// Читаем файл сначала для подсчёта общего количества
		file.Seek(0, 0)
		scanner := bufio.NewScanner(file)
		totalLines = 0
		matchedLines = 0
		for scanner.Scan() {
			totalLines++
			var log LogEntry
			if json.Unmarshal(scanner.Bytes(), &log) == nil && log.Level >= priority {
				matchedLines++
			}
		}
	}
	
	return result, totalLines, matchedLines, nil
}

// Оптимизированный обработчик (использует чтение с конца файла)
func (app *App) apiLogsOptimizedHandler(w http.ResponseWriter, r *http.Request) {
	// Парсим параметры
	priorityParam := r.URL.Query().Get("priority")
	limitParam := r.URL.Query().Get("limit")
	
	// Значения по умолчанию
	priority := 0
	limit := 100
	
	// Парсим приоритет
	if priorityParam != "" {
		if p, err := strconv.Atoi(priorityParam); err == nil && p >= 0 && p <= 4 {
			priority = p
		}
	}
	
	// Парсим лимит
	if limitParam != "" {
		if l, err := strconv.Atoi(limitParam); err == nil && l > 0 {
			if l > 1000 {
				l = 1000
			}
			limit = l
		}
	}
	
	// Читаем последние логи
	logs, total, filtered, err := app.readLastLogs(priority, limit)
	if err != nil {
		app.JSONError(w, "Failed to read logs: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Формируем ответ
	response := LogsResponse{
		Logs:      logs,
		Total:     total,
		Filtered:  filtered,
		Returned:  len(logs),
		Timestamp: time.Now().Unix(),
	}
	
	app.JSONResponse(w, response, http.StatusOK)
}


func (app *App) logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Удаляем куку
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
		"Username": claims.Username,
		"FilesInTrie": filesInTrie,
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


// Статические файлы
func (app *App) staticHandler() http.Handler {
	return http.StripPrefix("/static/", http.FileServer(http.Dir("./static")))
}

// Настройка маршрутов
func (app *App) setupRoutes() {
	// Статические файлы
	app.Router.PathPrefix("/static/").Handler(app.staticHandler())
	
	// Публичные маршруты
	app.Router.HandleFunc("/login", app.loginHandler).Methods("GET", "POST")
	app.Router.HandleFunc("/logout", app.logoutHandler).Methods("GET", "POST")
	
	// Защищенные маршруты
	protected := app.Router.PathPrefix("/").Subrouter()
	protected.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(app.AuthMiddleware(next.ServeHTTP))
	})
	
	protected.HandleFunc("/", app.indexHandler).Methods("GET")
	protected.HandleFunc("/logs", app.logsHandler).Methods("GET")
	
	protected.HandleFunc("/api/logs", app.apiLogsHandler).Methods("GET")
	
}

// Запуск сервера
func (app *App) Run() {
	if !app.Config.Enabled {
		return
	}
	app.setupRoutes()
	
	addr := app.Config.Listen
	app.Logger.Event(LOG_INFO, "admin", fmt.Sprintf("Admin panel listening at %s", addr))
	fmt.Println("Admin panel listening at", addr)
	err := http.ListenAndServe(addr, app.Router)
	if (err != nil) {
		fmt.Println("app error:", err)
	}
}
