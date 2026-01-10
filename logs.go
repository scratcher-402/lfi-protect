package main

import (
	"fmt"
	"os"
	"path/filepath"
	"encoding/json"
	"time"
	"net/http"
	)

const (
	LOG_DEBUG = 0
	LOG_INFO = 1
	LOG_WARNING = 2
	LOG_ERROR = 3
	LOG_FATAL = 4
	)

type Logger struct {
	config *LogsConfig
	accessLogFile *os.File
	errorLogFile *os.File
	infoJsonlFile *os.File
	infoJsonlPath string
	}

func NewLogger(config *LogsConfig) (*Logger, error) {
	logsDir := config.LogsPath
	err := os.MkdirAll(logsDir, 0755)
	if (err != nil) {
		return nil, fmt.Errorf("Logs path creating error: %w", err)
	}
	accessLogFile, err := os.OpenFile(filepath.Join(logsDir, "access.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if (err != nil) {
		return nil, fmt.Errorf("access.log file creating error: %w", err)
	}
	errorLogFile, err := os.OpenFile(filepath.Join(logsDir, "error.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if (err != nil) {
		return nil, fmt.Errorf("error.log file creating error: %w", err)
	}
	infoJsonlFile, err := os.OpenFile(filepath.Join(logsDir, "info.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if (err != nil) {
		return nil, fmt.Errorf("info.jsonl file creating error: %w", err)
	}
	return &Logger{config: config,
				   accessLogFile: accessLogFile,
				   errorLogFile: errorLogFile,
				   infoJsonlFile: infoJsonlFile,
				   infoJsonlPath: filepath.Join(logsDir, "info.jsonl")}, nil
}

type LogEvent struct {
	Level int
	Message string
	UnixTime int64
	Category string
	}

func NewEvent(level int, category string, message string) *LogEvent {
	unixTime := time.Now().Unix()
	return &LogEvent{Level: level, Category: category, Message: message, UnixTime: unixTime}
	}

func (e *LogEvent) Json() ([]byte, error) {
	data, err := json.Marshal(*e)
	if err != nil {
		return []byte{}, err
	}
	return data, nil
	}

func EventFromJSON (data []byte) (*LogEvent, error) {
	event := &LogEvent{}
	err := json.Unmarshal(data, event)
	if err != nil {
		return nil, err
	}
	return event, nil
}

func (logger *Logger) Event(level int, category string, message string) {
	event := NewEvent(level, category, message)
	data, err := event.Json()
	if err != nil {
		fmt.Println("Logging error:", err)
	}
	_, err = logger.infoJsonlFile.Write(data)
	if err != nil {
		fmt.Println("Log writing error:", err)
	}
	_, err = logger.infoJsonlFile.Write([]byte("\n"))
	if err != nil {
		fmt.Println("Log writing error:", err)
	}
}

func (logger *Logger) ProxyAccess(resp *http.Response) {
	r := resp.Request
	message := fmt.Sprintf("%s %s %s (%s)", r.Method, r.URL.Path, resp.Status, r.UserAgent())
	timeNow := time.Now()
	logger.Event(LOG_INFO, "proxy", message)
	timeString := timeNow.Format(time.RFC1123)
	accessLogMessage := fmt.Sprintf("[%s] %s\n", timeString, message)
	_, err := logger.accessLogFile.Write([]byte(accessLogMessage))
	if err != nil {
		fmt.Println("Logs writing error:", err)
	}
}

func (logger *Logger) ProxyError(r *http.Request, blocked bool, err error) {
	var message string
	if blocked {
		message = fmt.Sprintf("[BLOCKED] %s %s (%s) %s", r.Method, r.URL.Path, r.UserAgent(), err.Error())
	} else {
		message = fmt.Sprintf("%s %s (%s) %s", r.Method, r.URL.Path, r.UserAgent(), err.Error())
	}
	timeNow := time.Now()
	logger.Event(LOG_ERROR, "proxy", message)
	fmt.Println("proxy error")
	timeString := timeNow.Format(time.RFC1123)
	errorLogMessage := fmt.Sprintf("[%s] %s\n", timeString, message)
	_, err = logger.errorLogFile.Write([]byte(errorLogMessage))
	if err != nil {
		fmt.Println("Logs writing error:", err)
	}
}