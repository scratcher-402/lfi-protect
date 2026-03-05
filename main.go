package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Proxy ProxyConfig `yaml:"proxy"`
	Files FilesConfig `yaml:"files"`
	Logs  LogsConfig  `yaml:"logs"`
	Admin AdminConfig `yaml:"admin"`
}
type ProxyConfig struct {
	ListenAddr     string   `yaml:"listen"`
	ServerAddr     string   `yaml:"server"`
	MaxReqBodySize int      `yaml:"max-req-body-size"`
	CheckURL       bool     `yaml:"check-url"`
	CheckQuery     bool     `yaml:"check-query"`
	CheckFilenames bool     `yaml:"check-filenames"`
	CheckJSON      bool     `yaml:"check-json"`
	CheckAllFields bool     `yaml:"check-all-fields"`
	CheckFields    []string `yaml:"check-fields"`
	CheckFileLeaks bool     `yaml:"check-file-leaks"`
	BlockEnabled   bool     `yaml:"block-enabled"`
	BlockErrorRate int 	    `yaml:"block-error-rate"`
	BlockInterval  int 	    `yaml:"block-interval"`
}
type FilesConfig struct {
	Paths       []string `yaml:"paths"`
	Exclude     []string `yaml:"exclude"`
	MinDepth    int      `yaml:"min-depth"`
	DetectDepth int      `yaml:"detect-depth"`
}
type LogsConfig struct {
	LogsPath        string `yaml:"logs-path"`
	ConsoleLogLevel int    `yaml:"console-log-level"`
}
type AdminConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Listen   string `yaml:"listen"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func main() {
	configFile, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Println("Config reading error:", err)
		return
	}
	var config Config
	err = yaml.Unmarshal(configFile, &config)
	if err != nil {
		log.Println("Config parsing error:", err)
		return
	}
	for _, path := range config.Files.Paths {
		path, err = filepath.Abs(path)
		if err != nil {
			log.Println("Path error", err)
		}
	}
	for _, path := range config.Files.Exclude {
		path, err = filepath.Abs(path)
		if err != nil {
			log.Println("Path error", err)
		}
	}
	logger, err := NewLogger(&config.Logs)
	if err != nil {
		log.Println("Logger creating error:", err)
		return
	}
	ipban := NewIPBan(time.Duration(config.Proxy.BlockInterval) * time.Second, config.Proxy.BlockErrorRate, logger)
	trie := NewTrie(&config.Files, logger)
	err = trie.Setup()
	trie.Korasikify()
	if err != nil {
		fmt.Println("Trie building error:", err)
		return
	}
	log.Println("Target URL:", config.Proxy.ServerAddr)
	log.Println("Listening:", config.Proxy.ListenAddr)
	proxy, err := NewProxy(&config.Proxy, trie, logger, ipban)
	if err != nil {
		log.Println("Proxy creating error:", err)
		return
	}
	app, err := NewApp(&config.Admin, logger, trie, proxy)
	if err != nil {
		log.Println("Admin app creating error")
	}
	go app.Run()
	log.Println("Scr-LFI-Protect is running")
	http.ListenAndServe(config.Proxy.ListenAddr, proxy)
}
