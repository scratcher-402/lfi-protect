package main
import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"gopkg.in/yaml.v3"
	)

type Config struct {
	Proxy ProxyConfig `yaml:"proxy"`
	Files FilesConfig `yaml:"files"`
	Logs LogsConfig `yaml:"logs"`
}
type ProxyConfig struct {
	ListenAddr string `yaml:"listen"`
	ServerAddr string `yaml:"server"`
	MaxReqBodySize int `yaml:"max-req-body-size"`
	CheckURL bool `yaml:"check-url"`
	CheckQuery bool `yaml:"check-query"`
	CheckFilenames bool `yaml:"check-filenames"`
	CheckJSON bool `yaml:"check-json"`
	CheckAllFields bool `yaml:"check-all-fields"`
	CheckFields []string `yaml:"check-fields"`
	CheckFileLeaks bool `yaml:"check-file-leaks"`
}
type FilesConfig struct {
	Paths []string `yaml:"paths"`
	Exclude []string `yaml:"exclude"`
}
type LogsConfig struct {
	LogsPath string `yaml:"logs-path"`
}

func main() {
	configFile, err := os.ReadFile("config.yaml")
	if (err != nil) {
		fmt.Println("Config reading error:", err)
		return
	}
	var config Config
	err = yaml.Unmarshal(configFile, &config)
	if (err != nil) {
		fmt.Println("Config parsing error:", err)
		return
	}
	fmt.Println("Scr-LFI-Protect")
	for _, path := range config.Files.Paths {
		path, err = filepath.Abs(path)
		if err != nil {
			fmt.Println("Path error", err)
		}
	}
	for _, path := range config.Files.Exclude {
		path, err = filepath.Abs(path)
		if err != nil {
			fmt.Println("Path error", err)
		}
	}
	logger, err := NewLogger(&config.Logs)
	if err != nil {
		fmt.Println("Logger creating error:", err)
		return
	}
	trie := NewTrie(&config.Files, logger)
	err = trie.Setup()
	if err != nil {
		fmt.Println("Trie building error:", err)
		return
	}
	fmt.Println("Target URL:", config.Proxy.ServerAddr)
	fmt.Println("Listening:", config.Proxy.ListenAddr)
	proxy, err := NewProxy(&config.Proxy, trie, logger)
	if (err != nil) {
		fmt.Println("Proxy creating error:", err)
		return
	}
	http.ListenAndServe(config.Proxy.ListenAddr, proxy)
	}
