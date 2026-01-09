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
		
		data := map[string]interface{}{
			"Title": "Вход в систему",
		}
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
		app.JSONResponse(w, map[string]string{"message": "Успешный выход"}, http.StatusOK)
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
